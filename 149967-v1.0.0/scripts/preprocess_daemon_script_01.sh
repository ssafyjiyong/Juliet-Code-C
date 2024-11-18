#!/bin/bash

inotifywait -m -e create --format "%f" /opt/stonesoup/workspace/testData/ | while read NEW_FILE; do if [[ "${NEW_FILE}" == *.pid ]]; then PROC_ID="${NEW_FILE%.pid}"; echo "Signaling: " "${PROC_ID}" && echo "Waiting" && sleep 0.5 && kill -s 10 "${PROC_ID}" && echo "Signaled."; else echo "Ignoring: " "/opt/stonesoup/workspace/testData/${NEW_FILE}"; fi; done;