#!/bin/bash

# Kill any existing Polybar instances
pkill -x polybar

# Wait until they're gone
while pgrep -x polybar >/dev/null; do sleep 0.2; done

# Launch your bar (edit 'mybar' to match your [bar/mybar] section)
polybar prbar &
