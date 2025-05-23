import requests
from datetime import datetime

'''requests.post("http://127.0.0.1:8000/items/", json=({
  "id": 0,
  "name": "Dubios Camron Throne",
  "value": 8.5,
  "description": "Buffs Health by 4500 and Stamina by 2800 and increases Stamina recovery by 480.",
  "count": 46,
  "category": "Beverage"
}))'''

'''requests.post("http://127.0.0.1:8000/items/", json=({
  "id": 1,
  "name": "Orzorga's Smoked Bearhunch",
  "value": 20.0,
  "description": "Buffs Health by 4500 and increases Magicka and Stamina recovery by 480.",
  "count": 16,
  "category": "Food"
}))'''

'''requests.post("http://127.0.0.1:8000/items/", json=({
  "id": 2,
  "name": "Tristat Potion",
  "value": 13.0,
  "description": "Instantly replenishes Health by 9800 and Magicka and Stamina by 7500 and increasing Health, Magicka, and Stamina recovery by 280.",
  "count": 1400,
  "category": "Potion"
}))'''

'''requests.put("http://127.0.0.1:8000/items/", params={"item_id": 0, "count": 38})'''

'''requests.delete("http://127.0.0.1:8000/items/", params={"item_id": 2})'''

'''requests.post("http://127.0.0.1:8000/users/", json=({
  "id": 0,
  "name": "Gaith Adra",
  "email": "gaithgagaga@gmail.com",
  "created_at": datetime.now().isoformat(),
  "password": "WelloHW",
  "is_admin": True
}))'''

'''requests.post("http://127.0.0.1:8000/users/", json=({
  "id": 1,
  "name": "Tony Smith",
  "email": "tony.smithy@gmail.com",
  "created_at": datetime.now().isoformat(),
  "password": "helloPW",
  "is_admin": False
}))'''

'''requests.post("http://127.0.0.1:8000/users/", json=({
  "id": 2,
  "name": "Marco Rash",
  "email": "marco.r@gmail.com",
  "created_at": datetime.now().isoformat(),
  "password": "newPw",
  "is_admin": False
}))'''

'''requests.put("http://127.0.0.1:8000/users/", params={"username": "Gaith Adra", "user_pw": "WelloHW", "user_id": 2, "email": "marco.r@gmail.com"})'''


'''requests.delete("http://127.0.0.1:8000/users/", params={"username": "Gaith Adra", "user_pw": "WelloHW", "user_id": 2})'''
