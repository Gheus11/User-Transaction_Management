import requests

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

'''requests.post("http://127.0.0.1:8000/users/", params=({
  "name": "Gaith Adra",
  "email": "gaithgagaga@gmail.com",
  "password": "WelloHW",
}))'''

'''requests.post("http://127.0.0.1:8000/users/", params=({
  "name": "John Marji",
  "email": "jm.3@gmail.com",
  "password": "kellowh",
}))'''

'''requests.post("http://127.0.0.1:8000/users/", params=({
  "name": "Tony Smith",
  "email": "tony.smithy@gmail.com",
  "password": "helloPW"
}))'''

'''requests.post("http://127.0.0.1:8000/create_user/", params=({
  "name": "Alice Larren",
  "email": "a.l.2025@gmail.com",
  "password": "WelloHW",
}))'''

'''requests.put("http://127.0.0.1:8000/update_user/", params={"username": "Alice Larren", "user_pw": "WelloHW", "email": "a.larr.2025@gmail.com"})'''


'''requests.delete("http://127.0.0.1:8000/delete_user/", params={"username": "Alice Larren", "user_pw": "WelloHW", "user_to_delete": "Alice Larren"})'''

'''requests.post("http://127.0.0.1:8000/add_transaction/", params={"username": "Gaith Adra", "password": "WelloHW", "money_earned": 3.0})'''

'''requests.put("http://127.0.0.1:8000/update_transaction/", params={"username": "Gaith Adra", "password": "WelloHW", "transaction_id": 2, "money_earned": 4.20})'''

'''requests.delete("http://127.0.0.1:8000/delete_transaction/", params={"username": "Gaith Adra", "password": "WelloHW", "transaction_id": 2})'''