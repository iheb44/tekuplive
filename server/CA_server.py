import pika
import json


def request_certificate(client_id):
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
 
    channel.queue_declare(queue='certificate_request_queue')
 
    client_data = {
        "client_id": client_id
    }
 
    channel.basic_publish(exchange='',
                          routing_key='certificate_request_queue',
                          body=json.dumps(client_data))
    print(f"demande de certification a ete envoyer pour {client_id}")
    connection.close()
 
if __name__ == "__main__":
    client_id = input("donner login: ")
    request_certificate(client_id)
