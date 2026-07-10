CREATE TRIGGER audit_entries_no_replace
BEFORE INSERT ON audit_entries
WHEN EXISTS (
    SELECT 1 FROM audit_entries
    WHERE sequence = NEW.sequence OR entry_hash = NEW.entry_hash
)
BEGIN
    SELECT RAISE(ABORT, 'audit entries cannot be replaced');
END;

CREATE TRIGGER action_events_no_update
BEFORE UPDATE ON action_events
BEGIN
    SELECT RAISE(ABORT, 'action events are append-only');
END;

CREATE TRIGGER action_events_no_delete
BEFORE DELETE ON action_events
BEGIN
    SELECT RAISE(ABORT, 'action events are append-only');
END;

CREATE TRIGGER execution_plans_no_update
BEFORE UPDATE ON execution_plans
BEGIN
    SELECT RAISE(ABORT, 'execution plans are immutable');
END;

CREATE TRIGGER execution_plans_no_delete
BEFORE DELETE ON execution_plans
BEGIN
    SELECT RAISE(ABORT, 'execution plans are immutable');
END;

CREATE TRIGGER sanitized_results_no_update
BEFORE UPDATE ON sanitized_results
BEGIN
    SELECT RAISE(ABORT, 'sanitized results are immutable');
END;

CREATE TRIGGER sanitized_results_no_delete
BEFORE DELETE ON sanitized_results
BEGIN
    SELECT RAISE(ABORT, 'sanitized results are immutable');
END;
