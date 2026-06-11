@echo off
cd /d C:\zai\zair
set "RUST_LOG=zair=info"
echo Starting zair at %date% %time% > C:\zai\zair\zair.log
target\release\zair.exe agent --name "ZAI Agent" --server https://aicq.online --model glm-4-plus >> C:\zai\zair\zair.log 2>&1
echo zair exited at %date% %time% >> C:\zai\zair\zair.log
