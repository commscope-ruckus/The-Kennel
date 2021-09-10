import paho.mqtt.client as mqtt #import the mqtt library
import sci_message_pb2 #import all SZ .proto classes compiled by the protoc tool

#read incoming messages
def on_message(client, userdata, message):
    scim = sci_message_pb2.SciMessage().FromString(message.payload)
    print(scim)
#    print(scim.apClient, scim.apClient.ap, scim.apClient.clients[0].clientMac,scim.apReport, scim.apWiredClient, scim.apStatus, scim.switchDetailMessage, scim.switchConfigurationMessage, scim.apRogue)

def main():
    broker_address="10.0.0.120"
    client = mqtt.Client("Python") #create new client
    client.on_message=on_message #attach function to message callback
    print("connecting to mosquitto broker")
    client.connect(broker_address) #connect to mosquitto broker
    print("Subscribing to sci-topic")
    client.subscribe("sci-topic")
    client.loop_forever() #starts a thread to read the message buffers

if __name__ == "__main__":
	main()
