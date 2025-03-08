# Shuttle 部署指南

本项目是一个基于 Shuttle 平台的自动化部署方案，可以通过 GitHub Actions 实现自动部署2go节点，每30天自动部署一次

## 部署流程

1. 注册 [Shuttle](https://www.shuttle.rs/) 账号并获取 API 密钥

4. 在 seettings➡secrets ansd variable➡中的actions里设置环境变量：`SHUTTLE_API_KEY`（填入你的 Shuttle API 密钥）
![image](https://github.com/user-attachments/assets/d67ab79b-8d1d-437e-8c6b-786163e197a2)

5. 其他环境变量也可在secrets ansd variable中添加
## 订阅 
https://<你的域名>/<SUB_PATH>
