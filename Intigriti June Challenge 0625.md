# Intigriti June Challenge 0625 - writeup
The challenge requires us to gain RCE on the server. The given web application is basically a notes app where we can login to store notes, upload files and also report urls to a bot. Here's the link to the challenge : https://challenge-0625.intigriti.io/
## Analyzing the web application
Beginning with the login page, we can observe in the dev tools that we have two cookies stored which are- "INSTANCE" and session cookie. On logging in, the page is updated without changing the URL, since it is a single-page web application based on Vue.js.
<br><br>
![Image](https://github.com/user-attachments/assets/2dadff4e-5efd-419c-b4e4-b2005c5c30ba)
<br><br>
After downloading the source code from the challenge website, we start analyzing the code : 
Following is the code for dockerfile : 
```
FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y wget unzip curl && \
    apt-get install -y chromium chromium-driver && \
    rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


RUN groupadd -r appuser && useradd -r -g appuser -m appuser

WORKDIR /app

COPY . /app

RUN RANDOM_FLAG="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)" && \
    RANDOM_FILENAME="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)" && \
    echo "INTIGRITI{$RANDOM_FLAG}" > /flag_$RANDOM_FILENAME.txt && \
    chmod 444 /flag_$RANDOM_FILENAME.txt && \
    echo "Flag copied to /flag_$RANDOM_FILENAME.txt"


RUN mkdir -p /app/instances && \
    chown -R appuser:appuser /app

ENV PATH="/usr/lib/chromium:${PATH}"
ENV CHROME_BIN="/usr/bin/chromium"
ENV CHROMEDRIVER_BIN="/usr/bin/chromedriver"

EXPOSE 1337

USER appuser

CMD ["python3", "app.py"]
```
So the flag is stored in a file with randomized file name.
On reviewing the utils.py file, we observe that we can upload any file but the filename is being sanitized.
```
def sanitize_filename(filename):
    return re.sub(r'[^A-Za-z0-9_/]', '', filename)
```
Similarly username is also sanitized but since '.' are allowed, we'll see later on that this can be used in path traversal.
```
def sanitize_username(username):
    return re.sub(r'[^A-Za-z0-9_.-]', '', username)
```
After that, on reading the app.py file, we understand how the instance cookie is being managed.
```
@app.before_request
def before_request():
    if request.endpoint != 'static':
        instance_id = get_or_create_instance_id()
        
        previous_instance = session.get('instance_id')
        
        if previous_instance and previous_instance != instance_id:
            logout_user()
        
        db_path = get_instance_path(instance_id, "app.db")
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        
        check_and_update_schema(db_path)
        
        with app.app_context():
            db.create_all()
```
The get_or_create_instance_id function is defined in the instance_manager.py file : 
```
    if 'instance_id' in session and is_valid_instance_id(session['instance_id']):
        return session['instance_id']
    
    instance_id = request.cookies.get('INSTANCE')
    
    if not is_valid_instance_id(instance_id):
        instance_id = str(uuid.uuid4())
        print(f"Creating new instance: {instance_id}")
    
    instance_dir = os.path.join(INSTANCES_DIR, instance_id)
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)
        os.makedirs(os.path.join(instance_dir, "notes"), exist_ok=True)
        os.makedirs(os.path.join(instance_dir, "chrome_profile"), exist_ok=True)
    
    update_instance_timestamp(instance_id, app=current_app)
    
    session['instance_id'] = instance_id
    
    return instance_id
```
So basically before every request, the code uses the get_or_create_instance_id function to get the instance_id from browser cookies and matches it with the instance tied to the session cookie. If they don't match, the user is logged out. In the get_or_create_instance_id function, it is checked whether the path of instance_dir exists or not. If it does not exists, then a directory corresponding to the current instance is created with two sub-directories - "notes" and "chrome-profile". The instance_dir variable has the path based on INSTANCE_DIR(variable defined in config.py as cwd/instances) and the instance_id.<br><br>
Here we can spot that the instance_id is not sanitized. So since it is used in directory creation, there is a potential path traversal vulnerability. We can set the "INSTANCE" cookie as '..' or something else and delete the session cookie to ensure that there is no instance associated with the current session.
<br>
<br>
Next checking out the utils.py file, we see the function setting up chromium settings for the bot. Interesting thing to note here is the `chrome_options.add_argument(f"--user-data-dir={get_instance_path(instance_id, 'chrome_profile')}")` line. In chromium, "--user-data-dir" flag allows you to specify a custom location for the user data directory, which contain files related to a individual chromium profile. 
