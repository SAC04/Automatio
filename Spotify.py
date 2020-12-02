import base64
import datetime
import requests
import json
import os
import spotipy
import spotipy.util as util
from spotipy.oauth2 import SpotifyOAuth
from spotipy import oauth2
from bottle import route, run, request


from urllib.parse import urlencode
from urllib.parse import quote

access_token = None
client_id = '951ede4b16b54085b9032a2f95b5c368'
client_secret = '6a7adf848d5449b1a25a4c06c89e6596'
token_url = "https://accounts.spotify.com/api/token"
redirect_uri = "http://127.0.0.1/8080/callback/"
cache = '.spotipyoauthcache'



def get_songslist():
    f = open("playInfo.json", "r")
    data = json.loads(f.read())
    song_arr=[]
    for i in data['items']:
        song_arr.append(i['snippet']['title'])
    f.close()
    return song_arr

# youtube_dl.YoutubeDL({}).extract_info(youtube_url, download=False)

def get_spotifytoken():
    spotify_token = "BQC0K5KhZeDXiPdeKokEqg7n8Moo8jz12GiYPAVCNS4T1is7_M59UI22Pe5LG5rYjVadpO3e2amIgTTxLAe4O9G1eNXKKfcYjiU2aOsYWPgn3lNEZbvUBjCCRDj4_zG_pupEgyk0JvIja2XhKYGhfcjylkaOM0fOjQZ6NXPNRrH68LZbSufBEuqkbtzc5mARWPQAKxSMspn2nSwJggzJMc2JM4m2hWwycUTFt99YSv5WkgT23tt9_lU"
    return spotify_token

def get_SpotifyID():
    spotify_userid = "juwdi1k8oh59r5vj70uyg5hgm"
    return spotify_userid

def open_file():
    f = open("MyFile.txt","a")

def get_client_credentials():
        """
        Returns a base64 encoded string
        """
        if client_secret == None or client_id == None:
            raise Exception("You must set client_id and client_secret")
        client_creds = f"{client_id}:{client_secret}"
        client_creds_b64 = base64.b64encode(client_creds.encode())
        return client_creds_b64.decode()

def get_token_headers():
        client_creds_b64 = get_client_credentials()
        return {
            "Authorization": f"Basic {client_creds_b64}"
        }

def get_token_data():
        return {
            "grant_type": "client_credentials"
        }


def add_songs(playlistID):
    songslist =  get_songslist()
    urilist = []
    for i in songslist:
        arr = i.split(" ")
        s=""
        if(len(arr)>=4):
            for j in range(4):
                s+=str(arr[j])
        else:
            s=i
        current = searchSong(s)
        if current!="":
            urilist.append(current)

    request_data = json.dumps(urilist)
    query = "https://api.spotify.com/v1/playlists/{}/tracks".format(playlistID)
    response = requests.post(
        query,
        data = request_data,
        headers = {
            "Content-Type" : "application/json",
            "Authorization": "Bearer {}".format(get_spotifytoken())
        }
    )

    response_json = response.json()
    return response_json
#        print(value)
#        urilist.append(value)

def create_playlist(playlist_name):

    request_body = json.dumps({
        "name" : playlist_name,
        "description" : "All song from youtube playlist",
        "public" : True
    })

    query = "https://api.spotify.com/v1/users/{}/playlists".format(
    get_SpotifyID())

    response = requests.post(
        query,
        data = request_body,
        headers = {
            "Content-Type" : "application/json",
            "Authorization": "Bearer {}".format(get_spotifytoken())
        }
    )
    response_json = response.json()
    # print(response_json)
    return response_json['id']
    
def transfer_playlist(playlist_name):
    playlist_id = create_playlist(playlist_name)
    add_songs(playlist_id)

def perform_auth():
        token_data = get_token_data()
        token_headers = get_token_headers()
        r = requests.post(token_url, data=token_data, headers=token_headers)
        if r.status_code not in range(200, 299):
            raise Exception("Could not authenticate client.")
            # return False
        data = r.json()
        access_token = data['access_token']
        return access_token

def get_resource_header():
        access_token = get_spotifytoken()
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        return headers

def get_userID():
    headers = get_resource_header()
    endpoint = "https://api.spotify.com/v1/me"
    r = requests.get(endpoint , headers = headers)
    print(r.json())

#def create_playlist(playList_name):

def Dump_It(response, filename):
    out_file = open(filename, "w")
    y = json.dump(response , out_file, indent = 6)
    out_file.close()

def searchSong(songname):

    headers = get_resource_header()
    endpoint = "https://api.spotify.com/v1/search"
    data = urlencode({"q": songname, "type": "track" , "limit": "1"})
    lookup_url = f"{endpoint}?{data}"
    r = requests.get(lookup_url, headers = headers)
    if not r.json()['tracks']['items']:
        return ""
    else:
        select_song = r.json()['tracks']['items'][0]['uri']
        return select_song

if __name__ == '__main__':
    transfer_playlist("Hip-Hop")