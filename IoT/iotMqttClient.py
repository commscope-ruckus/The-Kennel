import paho.mqtt.client as mqtt #import the mqtt library
import json

#read incoming messages
def on_message(client, userdata, message):
    message = json.loads(message.payload)
    #print (message)
    print ("Centralite Door Sensor Reading")
    print ('{:<14s} {:<20s}'.format("device_euid: ", message['device_euid']))       
    print ('{:<14s} {:<20s}'.format("gateway_euid: ", message['gateway_euid'])) 
    print ('{:<14s} {:<20s}'.format("endpoint_id: ", str(message['endpoint_id']))) 
    print ('{:<14s} {:<20s}'.format("cluster_id: ", message['cluster_id'])) 
    print ('{:<14s} {:<20s}'.format("attribute_id: ", message['attributes'][0]['attribute_id'])) 
    print ('{:<14s} {:<20s}'.format("value: ", message['attributes'][0]['value'])) 
    
def main():
    broker_address="10.0.0.63"
    client = mqtt.Client("Python") #create new client
    client.on_message=on_message #attach function to message callback
    print("connecting to mosquitto broker")
    client.connect(broker_address) #connect to mosquitto broker
    print("Subscribing to /devices")
    client.subscribe("/devices")
    client.loop_forever() #starts a thread to read the message buffers

if __name__ == "__main__":
	main()
