from flask import Flask, render_template, request, redirect, session
import requests
import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

app = Flask(__name__)
 
@app.route('/portal')
def form():
    session['clientMac'] = request.args.get('client_mac')
    session['clientIp'] =request.args.get('uip')
    session['szIp'] = request.args.get('nbiIP')
    session['clientUrl'] = request.args.get('url')
    session['startUrl'] = request.args.get('StartURL')
    return render_template('wisprPortal.html')

@app.route('/data/', methods = ['POST'])
def data():
    if request.method == 'POST':
        name = request.form.get('username')
        password = request.form.get('password')
        url = "https://" + session.get('szIp') + ":9443/portalintf"
        body = {
            "Vendor": "ruckus",
            "RequestPassword": "ruckus123!",
            "APIVersion": "1.0",
            "RequestCategory": "UserOnlineControl",
            "RequestType": "Login",
            "UE-Proxy": "0",
            "UE-IP": session.get('clientIp'),
            "UE-MAC": session.get('clientMac'),
            "UE-Username": name,
            "UE-Password": password
            }
        response = requests.post(url, json = body, verify = False)
        if session.get('startUrl') != None:
            return redirect(session.get('startUrl'), code=302)
        else:
            return redirect(session.get('clientUrl'), code=302)

def main():
    app.secret_key = 'super secret key'
    app.run(host='10.0.0.180', port=5000)

if __name__ == "__main__":
	main()