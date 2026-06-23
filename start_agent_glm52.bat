@echo off
cd /d C:\zai\zair
set "RUST_LOG=zair=info"
echo Starting zair agent at %date% %time% > C:\zai\zair\zair.log
target\release\zair.exe agent --name "ZAI Agent" --server https://aicq.me --model glm-5.2 >> C:\zai\zair\zair.log 2>&1
echo zair exited at %date% %time% >> C:\zai\zair\zair.log
