/* Read-only rendered DOM export. No page code or resource is replayed. */
(() => {
  const limit = 20 * 1024 * 1024;
  const nodes = [], gaps = [], seen = new WeakSet();
  let size = 0;
  const secrets = new Set();
  const clean = value => {
    let text = String(value || '');
    for (const secret of secrets) if (secret) text = text.split(secret).join('[REDACTED]');
    return text.replace(/https?:\/\/[^\s<>"']+/gi, '[URL]')
      .replace(/[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}/g, '[EMAIL]')
      .replace(/\beyJ[\w-]+\.[\w-]+(?:\.[\w-]+)?/g, '[TOKEN]')
      .replace(/\b(?:Bearer\s+|(?:password|token|cookie|secret|otp)\s*[:=]\s*)[^\s"<>]+/gi, '[REDACTED]')
      .replace(/\b[A-Za-z0-9_+\/-]{32,}={0,2}\b/g, '[OPAQUE]')
      .replace(/\b\d{4,}\b/g, '[NUMBER]');
  };
  // Scan all accessible roots before serializing so values cannot leak via text.
  const scan = root => {
    if (seen.has(root)) return;
    seen.add(root);
    for (const el of root.querySelectorAll('*')) {
      if (['INPUT','TEXTAREA','SELECT'].includes(el.tagName) && el.value) secrets.add(String(el.value));
      if (el.shadowRoot) scan(el.shadowRoot);
      if (el.tagName === 'IFRAME') {
        try { if (el.contentDocument) scan(el.contentDocument); } catch (_) { /* recorded below */ }
      }
    }
  };
  const stack = [{node: document.documentElement, parent: null, relation: 'document'}];
  try {
    scan(document);
    while (stack.length) {
      const {node, parent, relation, redact = false} = stack.pop();
      if (!node || ![1,3].includes(node.nodeType)) continue;
      const item = {index: nodes.length, parent, relation};
      if (node.nodeType === 3) {
        item.text = redact ? '[REDACTED]' : clean(node.textContent);
      } else {
        item.tag = node.tagName.toLowerCase(); item.attrs = {};
        const identity = /(?:account|profile|user)[-_ ]?(?:name|email|identity)/i.test(
          [node.id, node.getAttribute('data-testid'), node.getAttribute('aria-label')].join(' '));
        for (const attr of Array.from(node.attributes)) {
          if (/^(class|id|role|type|name|title|lang|disabled|hidden|tabindex|data-testid|aria-(label|labelledby|describedby|expanded|selected|disabled|hidden))$/.test(attr.name)) {
            item.attrs[attr.name] = (identity || redact) && ['aria-label','title'].includes(attr.name) ? '[IDENTITY]' : clean(attr.value);
          }
        }
        const win = node.ownerDocument.defaultView;
        const rect = node.getBoundingClientRect(), style = win.getComputedStyle(node);
        let visible = rect.width > 0 && rect.height > 0;
        for (let el = node; el; el = el.parentElement) {
          const s = win.getComputedStyle(el);
          if (s.display === 'none' || s.visibility === 'hidden' || Number(s.opacity) === 0) visible = false;
        }
        item.layout = {x:rect.x,y:rect.y,width:rect.width,height:rect.height,visible,
          disabled:!!node.disabled,pointer_events:style.pointerEvents};
        if (node.matches('button,a,input,select,textarea,[role="button"]')) {
          const hit = node.ownerDocument.elementFromPoint(rect.x + rect.width/2, rect.y + rect.height/2);
          item.layout.center_hit = !!hit && (hit === node || node.contains(hit));
        }
        const blocked = redact || identity || ['script','style','noscript','input','textarea','select'].includes(item.tag)
          || node.hasAttribute('contenteditable');
        if (blocked) item.redacted_content = true;
        {
          const children = Array.from(node.childNodes);
          for (let i=children.length-1;i>=0;i--) stack.push({node:children[i],parent:item.index,relation:'child',redact:blocked});
        }
        if (node.shadowRoot) {
          const children = Array.from(node.shadowRoot.childNodes);
          for (let i=children.length-1;i>=0;i--) stack.push({node:children[i],parent:item.index,relation:'shadow',redact:blocked});
        } else if (item.tag.includes('-')) gaps.push({index:item.index,reason:'shadow_root_unobservable'});
        if (item.tag === 'iframe') {
          try {
            if (!node.contentDocument?.documentElement) throw Error();
            stack.push({node:node.contentDocument.documentElement,parent:item.index,relation:'frame'});
          } catch (_) { gaps.push({index:item.index,reason:'frame_unavailable'}); }
        }
      }
      size += new TextEncoder().encode(JSON.stringify(item)).length + 1;
      if (size > limit) return {format:'rendered-dom-v1',error:'dom_full_size_limit'};
      nodes.push(item);
    }
    return {format:'rendered-dom-v1',nodes,gaps,
      limitations:['closed_shadow_roots_cannot_be_detected_reliably'],complete:gaps.length === 0};
  } catch (_) { return {format:'rendered-dom-v1',error:'dom_full_capture_failed'}; }
})()
