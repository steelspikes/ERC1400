# Imagen base ligera con Node.js 10
FROM node:10.24.1-alpine

# Instala dependencias necesarias del sistema y Python 2.7
RUN apk add --no-cache \
    python2 \
    py2-pip \
    build-base \
    git \
    bash \
    curl \
    make \
    g++ \
    && ln -sf python2 /usr/bin/python \
    && pip install --upgrade pip

# Instala Yarn, Truffle y Ganache
RUN npm install -g yarn --force

# Crea un directorio de trabajo
WORKDIR /erc1400

# Copia el contenido del proyecto al contenedor
COPY . .

RUN git config --global url.https://github.com/.insteadOf git://github.com/

# # Instala dependencias del proyecto
RUN yarn install

# # Expone el puerto por si usas Ganache
# EXPOSE 8545

# # Comando por defecto (puedes cambiarlo a bash si quieres un shell)
# CMD ["yarn", "truffle", "test"]

# ENTRYPOINT ["sh", "-c", "yarn truffle migrate --network ganache" ]

CMD ["sh"]