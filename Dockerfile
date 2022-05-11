FROM quay.io/domino/python-public:3.8.7-slim
USER root
ADD requirements.txt .
ENV PATH=$PATH:/app/.local/bin:/app/bin
ENV PYTHONUNBUFFERED=true
ENV PYTHONUSERBASE=/home/app
ENV FLASK_ENV=production
ENV LOG_LEVEL=WARNING
RUN pip install --upgrade pip
RUN pip install --user -r requirements.txt
ADD src/mutation /app
RUN mkdir /tmp/domino
RUN apt-get update && apt-get upgrade -y
#USER 1000
ENTRYPOINT ["python",  "/app/app_vault_sidecar.py"]