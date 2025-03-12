# Shuttle 部署指南

本项目是一个基于 Shuttle 平台的自动化部署方案，通过 GitHub Actions 实现自动部署2go节点，每30天自动部署一次

## 部署流程
1. Fork 本项目
2. 注册 [Shuttle](https://www.shuttle.rs/) 账号并获取 API 密钥
![image](https://github.com/user-attachments/assets/68bf5dc6-8884-4ba6-b88b-b47b66878092)

3. 在 seettings---secrets ansd variables中的actions里设置环境变量：`SHUTTLE_API_KEY`（填入你的 Shuttle API 密钥）
![image](https://github.com/user-attachments/assets/d67ab79b-8d1d-437e-8c6b-786163e197a2)

4. 安装环境时间稍长，预计部署时间需要10分钟，请耐心等待，在actions中查看进度
## 订阅 
https://<你的域名>/sub
