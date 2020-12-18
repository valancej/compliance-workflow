FROM registry.access.redhat.com/ubi8/python-36

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python"] 
CMD ["app.py"]

