from app.parsers import auth_log

# Maps the "source" name clients send to the parser that handles it.
PARSERS = {
    auth_log.LOG_SOURCE: auth_log.parse_line,
}
