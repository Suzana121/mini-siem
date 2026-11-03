# Sourced by the web-* scenarios: waits until the nginx victim answers.
WEB="${WEB_HOST:-nginx}"
i=0
until curl -s -o /dev/null "http://$WEB/"; do
    i=$((i + 1))
    [ "$i" -ge 30 ] && echo "nginx not reachable" >&2 && exit 1
    sleep 1
done
