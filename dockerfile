# Use uma imagem base oficial do Node
FROM node:18-alpine

# Define o diretório de trabalho dentro do container
WORKDIR /usr/src/app

# Copia os arquivos de dependências
COPY package*.json ./

# Instala as dependências
# O PDF pede uma etapa de "Install" no CI, aqui garantimos na imagem também
RUN npm install

# Copia o restante do código fonte
COPY . .

# Expõe a porta que a API usa (geralmente 3000 ou 8080)
EXPOSE 3000

# Comando para iniciar a aplicação
CMD ["npm", "start"]