from app.parsers import auth_log, nginx_access, windows_event

# Maps the "source" name clients send to the parser that handles it.
PARSERS = {
    auth_log.LOG_SOURCE: auth_log.parse_line,
    nginx_access.LOG_SOURCE: nginx_access.parse_line,
    windows_event.LOG_SOURCE: windows_event.parse_line,
}
