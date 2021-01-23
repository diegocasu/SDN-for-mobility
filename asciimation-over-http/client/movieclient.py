from pathlib import Path
from time import sleep
import argparse
import requests


def parse_arguments():
    parser = argparse.ArgumentParser(description='Play an ASCII movie streamed by a remote server')

    parser.add_argument('--movie', action="store", dest="movie", type=str,
                        help="Movie to stream from the remote server")
    parser.add_argument('--serverIP', action="store", dest="server_IP", type=str,
                        help="IP address of the server", default="localhost")
    parser.add_argument('--serverPort', action="store", dest="server_port", type=str,
                        help="Listening port of the server", default="5000")

    return parser.parse_args()


def movie_end(frame):
    # Movie ends when no frames are returned.
    if not frame:
        return True

    return False


def clear_screen(number_lines):
    for _ in range(number_lines):
        # Move up the shell cursor and delete the whole line.
        print("\x1b[1A\x1b[2K", end="")


def play_frame(frame):
    frame_time = 0
    frame_time_scaling = 20
    drawn_lines = 0

    for index, line in enumerate(frame):
        if index == 0:
            # Time for which the frame must be shown on screen (in ms)
            frame_time = int(line)/frame_time_scaling
        else:
            print(line, end="")
            drawn_lines = drawn_lines + 1

    sleep(frame_time)
    return drawn_lines


def get_connection_lost_frame():
    # A movie is composed of frames, each one represented
    # by a certain number of lines in a text file.
    frame_path = (Path(__file__).parent / "connectionlost.txt").resolve()
    frame_start = 0
    frame_end = 13
    frame = []

    with open(frame_path, 'r') as connection_lost_frame:
        for index, line in enumerate(connection_lost_frame.readlines()):
            if frame_start <= index <= frame_end:
                frame.append(line)

            if index > frame_end:
                break

    return frame


def main():
    arguments = parse_arguments()

    if arguments.movie is None:
        print("Please specify the name of the movie as CLI argument")
        exit()

    frame_cursor = 0
    url = "http://" + arguments.server_IP + ":" + arguments.server_port + \
          "/movies/" + arguments.movie

    while True:
        server_response = None

        try:
            server_response = requests.get(url + "?frame=" + str(frame_cursor)).json()
        except Exception:
            print("Contacted server: " + arguments.server_IP + ":" + arguments.server_port)
            drawn_lines = play_frame(get_connection_lost_frame())
            clear_screen(drawn_lines + 2)

        if server_response is None:
            continue

        server_info = server_response["server"]
        frame = server_response["frame"]

        if movie_end(frame):
            break

        print("Contacted server: " + arguments.server_IP + ":" + arguments.server_port)
        print("Response from server: " + server_info)

        drawn_lines = play_frame(frame)
        clear_screen(drawn_lines + 2)
        frame_cursor = frame_cursor + 1

    print("Thanks for watching!")


if __name__ == '__main__':
    main()
