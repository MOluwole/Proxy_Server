from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import logging
import socket, threading, signal, sys, fnmatch, utils
from time import strftime, localtime

config = {
    "HOST_NAME": "127.0.0.1",
    "BIND_PORT": 8080,
    "MAX_REQUEST_LEN": 1024,
    "CONNECTION_TIMEOUT": 5,
    "BLACKLIST_DOMAINS": ["blocked.com"],
    "HOST_ALLOWED": ["*"],
    "COLORED_LOGGING": "true"
}

logging.basicConfig(level=logging.DEBUG,
                    format='[%(CurrentTime)-10s] (%(ThreadName)-10s) %(message)s',
                    )


class Server:
    def __init__(self, config):
        signal.signal(signal.SIGINT, self.shutdown)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((config['HOST_NAME'], config['BIND_PORT']))
        self.server_socket.listen(10)
        self.__clients = {}

    # @staticmethod
    # def get_tokens(input):
    #     tokens_by_slash = str(input.encode('utf-8')).split('/')
    #     all_tokens = []
    #     for i in tokens_by_slash:
    #         tokens = str(i).split('-')
    #         tokens_by_dot = []
    #         for j in range(0, len(tokens)):
    #             temp_tokens = str(tokens[j]).split('.')
    #             tokens_by_dot = tokens_by_dot + temp_tokens
    #         all_tokens = all_tokens + tokens + tokens_by_dot
    #     all_tokens = list(set(all_tokens))
    #     if 'com' in all_tokens:
    #         all_tokens.remove('com')
    #     if 'org' in all_tokens:
    #         all_tokens.remove('org')
    #     if 'www' in all_tokens:
    #         all_tokens.remove('www')
    #
    #     return all_tokens

    @staticmethod
    def read_data():
        all_url = './data/data.csv'
        print "PLEASE WAIT......"
        all_url_from_csv = pd.read_csv(all_url, ',', error_bad_lines=False)
        all_data = pd.DataFrame(all_url_from_csv)

        all_data = np.array(all_data)
        print "Reading Data from: ", all_url
        return all_data

    @staticmethod
    def train_classifier(all_data):
        labels = [d[1] for d in all_data]
        corpus = [d[0] for d in all_data]

        print "Extracting Text Features (Tokens and Corpus)"
        vec = TfidfVectorizer()
        features = vec.fit_transform(corpus)

        X_train, X_test, Y_train, Y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

        classifier = LogisticRegression()
        print "Training Classifier......."
        classifier.fit(X_train, Y_train)
        print "Classifier Score: ", classifier.score(X_test, Y_test)
        print "Training Done....Starting Proxy Server"
        return vec, classifier

    def listen(self, vec, classifier):
        while 1:
            (client_socket, client_address) = self.server_socket.accept()
            thread = threading.Thread(name=self.get_client_name(), target=self.proxy_thread,
                                      args=(client_socket, client_address, vec, classifier))
            thread.setDaemon(True)
            thread.start()
        self.shutdown(0, 0)

    @staticmethod
    def is_host_allowed(host):
        for wildcard in config['HOST_ALLOWED']:
            if fnmatch.fnmatch(host, wildcard):
                return True
        return False

    def proxy_thread(self, conn, client_address, vec, classifier):
        request = conn.recv(config['MAX_REQUEST_LEN'])
        first_line = request.split('\n')[0]
        url = first_line.split(' ')[1]

        # For Blacklisted Hosts
        for i in range(0, len(config['BLACKLIST_DOMAINS'])):
            if config['BLACKLIST_DOMAINS'][i] in url:
                self.log("FAIL", client_address, "BLACKLISTED: " + first_line)
                message = """<h1><center>This is Site has been Blacklisted</center></h1> <p><center>This site has 
                been blocked by the Admin. Contact the Administrator for more info </center></p> """
                conn.send(message)
                conn.close()
                return

        if not self.is_host_allowed(client_address[0]):
            message = """
                    <h1><center>Your IP Address is not allowed on this proxy server</center></h1>
                    <p><center>Contact the Administrator for access to this proxy server</center></p>
            """
            conn.send(message)
            conn.close()
            return

        self.log("WARNING", client_address, "REQUEST: " + first_line)

        http_pos = url.find("://")
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos + 3):]

        port_pos = temp.find(':')
        web_server_pos = temp.find('/')

        if web_server_pos == -1:
            web_server_pos = len(temp)

        if port_pos == -1 or web_server_pos < port_pos:
            port = 80
            web_server = temp[:web_server_pos]
        else:
            port = int((temp[(port_pos + 1):])[:web_server_pos - port_pos - 1])
            web_server = temp[:port_pos]

            # Check using ML
        print "TEMP", web_server
        predict = [web_server]
        predict = vec.transform(predict)
        label_prediction = classifier.predict(predict)

        print "PREDICTION", label_prediction

        if 'bad' in label_prediction[0]:
            message = """<h1><center>You have been blocked from visiting this site.</center></h1> <p><center>Reason: 
            This Website bears Similarities to phished Websites and our Machine Learning Algorithm has classified it 
            has a malicious Website</center></p> """
            conn.send(message)
            conn.close()
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config['CONNECTION_TIMEOUT'])
            sock.connect((web_server, port))
            sock.sendall(request)

            while True:
                data = sock.recv(config['MAX_REQUEST_LEN'])
                if len(data) > 0:
                    conn.send(data)
                else:
                    break
            sock.close()
            conn.close()
        except socket.error as error_message:
            self.log("ERROR", client_address, error_message)
            if sock:
                sock.close()
            if conn:
                conn.close()
            self.log("WARNING", client_address, "Peer Reset: " + first_line)
            self.log("ERROR", client_address, 'Error Message: ' + str(error_message))

    @staticmethod
    def get_client_name():
        return "Client"

    def shutdown(self):
        self.log("WARNING", -1, 'Shutting Down Proxy Server.....')
        main_thread = threading.currentThread()
        for t in threading.enumerate():
            if t is main_thread:
                continue
            self.log("FAIL ", -1, 'joining ' + t.getName())
            t.join()
        self.server_socket.close()
        sys.exit(0)

    @staticmethod
    def log(log_level, client, message):
        logger_dict = {
            'CurrentTime': strftime("%a, %d, %b, %Y, %X", localtime()),
            'ThreadName': threading.currentThread().getName()
        }
        if client == -1:
            formatted_message = message
        else:
            formatted_message = '{0}:{1} {2}'.format(client[0], client[1], message)
        logging.debug('%s', utils.colorizeLog(config['COLORED_LOGGING'], log_level, formatted_message),
                      extra=logger_dict)


if __name__ == '__main__':
    server = Server(config)
    vec, classifier = server.train_classifier(server.read_data())
    print "SERVER STARTED....."
    server.listen(vec, classifier)
