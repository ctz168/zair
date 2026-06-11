@echo off
set "RUST_LOG=zair=info"
cd /d C:\zai\zair
echo Starting zair agent at %date% %time% > C:\zai\zair\zair.log
C:\zai\zair\target\release\zair.exe agent --name "ZAI Agent" --server https://aicq.online --model glm-4-plus >> C:\zai\zair\zair.log 2>&1
echo zair exited at %date% %time% >> C:\zai\zair\zair.log
