TRINDADE EXPRESS — V4 PAINEL ADMINISTRATIVO

1) Instale Node.js LTS.
2) Abra esta pasta no VS Code.
3) No CMD do terminal, execute: npm install
4) Copie .env.example para .env e troque ADMIN_PASSWORD.
5) Execute: npm start
6) Cliente: http://localhost:3000
7) Admin: http://localhost:3000/admin.html

O painel administrativo permite visualizar todos os pedidos e alterar status.
Status disponíveis: Aguardando pagamento, Pagamento aprovado, Coleta agendada, Coletado, Em trânsito, Entregue, Cancelado.

IMPORTANTE: esta versão ainda usa arquivos JSON locais. Antes de publicar para clientes reais, migrar para PostgreSQL/Supabase/Neon, usar HTTPS, sessão segura, rate limiting, backup, LGPD, webhook de pagamento e uma API de rotas adequada para produção.
