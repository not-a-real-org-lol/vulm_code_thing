SECRET_KEY = "super-secret-key-123"
DEBUG = True


def search_vulnerable(request, MyModel):
    q = request.GET.get("q", "")
    rows = MyModel.objects.raw(f"SELECT * FROM myapp_mymodel WHERE name LIKE '%{q}%'")
    return rows


def save_comment_vulnerable(request, CommentModel):
    user_input = request.POST.get("comment", "")
    comment = CommentModel()
    comment.html = user_input
    comment.save()
    return comment


import os
def backup_vulnerable(request):
    filename = request.GET.get("file", "")
    os.system(f"tar -czf /backup/{filename}.tar.gz /data/{filename}")
    return "ok"


import pickle
def load_object_vulnerable(uploaded_file):
    data = uploaded_file.read()
    obj = pickle.loads(data)
    return obj


from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def update_profile_vulnerable(request):
    return "profile updated"


def get_user_data(username):
  db = sqlite3.connect("users.db")
  cursor = db.cursor()
  query = "SELECT * FROM users WHERE username = '" + username + "'"
  cursor.execute(query)
  user_data = cursor.fetchall()
  db.close()
  return user_data


def calculate_expression(expression):
    """
    Обчислює математичний вираз, переданий як рядок.
    """
    try:
        result = eval(expression)
        print(f"Результат: {result}")
        return result
    except Exception as e:
        print(f"Помилка: {e}")
        return None

# Приклад використання:
calculate_expression("2 + 3 * 4")


def run_user_expression():
    user_input = input("Enter math expression: ")
    result = eval(user_input)
    print("Result:", result)
