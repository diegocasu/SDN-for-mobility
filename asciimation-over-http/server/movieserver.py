import argparse
from flask import Flask, json
from flask import request
from pathlib import Path

MOVIE_SERVER = Flask(__name__)

SERVER_IP = ""
SERVER_PORT = ""
CATALOGUE = [
    {"name": "starwars", "path": "movies/starwars.txt", "frame size": 14}
]


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Stream an ASCII movie requested by a remote client')

    parser.add_argument('--serverIP', action="store", dest="server_IP", type=str,
                        help="IP address of the server", default="localhost")
    parser.add_argument('--serverPort', action="store", dest="server_port", type=str,
                        help="Listening port of the server", default="5000")

    return parser.parse_args()


def get_movie_descriptor(movie_name):
    movie_descriptor = None

    for movie in CATALOGUE:
        if movie["name"] == movie_name:
            movie_descriptor = movie
            break

    return movie_descriptor


def retrieve_movie_frame(movie_name, frame_number):
    movie_descriptor = get_movie_descriptor(movie_name)

    if movie_descriptor is None:
        return None

    # A movie is composed of frames, each one represented
    # by a certain number of lines in a text file.
    frame_start = frame_number*movie_descriptor["frame size"]
    frame_end = frame_number*movie_descriptor["frame size"] + movie_descriptor["frame size"] - 1
    requested_frame = []

    movie_path = (Path(__file__).parent / movie_descriptor["path"]).resolve()

    with open(movie_path, 'r') as movie_file:
        for index, line in enumerate(movie_file.readlines()):
            if frame_start <= index <= frame_end:
                requested_frame.append(line)

            if index > frame_end:
                break

    return requested_frame


@MOVIE_SERVER.route('/movies', methods=['GET'])
def get_movie_list():
    movie_list = []

    for movie in CATALOGUE:
        movie_list.append(movie["name"])

    return json.dumps(movie_list), 200


@MOVIE_SERVER.route('/movies/<movie_name>', methods=['GET'])
def get_movie_frame(movie_name):
    frame_number = request.args.get('frame', type=int)

    if frame_number is None:
        frame_number = 0

    response = {"server": SERVER_IP + ":" + SERVER_PORT,
                "frame": retrieve_movie_frame(movie_name, frame_number)}

    if response["frame"] is None:
        return json.dumps(response), 404

    return json.dumps(response), 200


def main():
    global SERVER_IP, SERVER_PORT, MOVIE_SERVER

    arguments = parse_arguments()
    SERVER_IP = arguments.server_IP
    SERVER_PORT = arguments.server_port

    MOVIE_SERVER.run(host=SERVER_IP, port=SERVER_PORT)


if __name__ == '__main__':
    main()
