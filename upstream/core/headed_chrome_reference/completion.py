"""Keep authentication outcomes distinct from bounded browser teardown."""
from .diagnostics import emit, step


def run_with_cleanup_result(worker, runtime):
    result = None
    failure = None
    try:
        runtime.check()
        with step(runtime.log, "worker_run", runtime):
            result = worker.run()
    except Exception as exc:
        failure = exc
    finally:
        runtime.finish()
    runtime.check_cancellation()
    if runtime.abort_source == "cleanup_deadline":
        if runtime.completed_result is not None:
            result = dict(runtime.completed_result)
            # This is only a candidate. Adapter identity/format checks still run
            # before any session or account is persisted.
            emit(runtime.log, "cleanup_outcome", result="candidate_retained")
            failure = None
        else:
            failure = getattr(worker, "_headed_auth_error", None) or failure
    if failure is not None:
        # A user's stop or an overall deadline takes precedence over other errors.
        if runtime.abort_source != "cleanup_deadline":
            runtime.check()
        raise failure
    runtime.check_result()
    return result
