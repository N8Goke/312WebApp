FROM python:3.8

WORKDIR /root

COPY . .

RUN pip3 install -r requirements.txt

EXPOSE 8080

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python3 -u app.py