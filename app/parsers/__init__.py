from app.parsers import auth_log, nginx_access

# Maps the "source" name clients send to the parser that handles it.
PARSERS = {
    auth_log.LOG_SOURCE: auth_log.parse_line,
    nginx_access.LOG_SOURCE: nginx_access.parse_line,
}
