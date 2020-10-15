# NearBY-API #

**Django Rest API for the Authentication. [Nearby Mobile Application](https://github.com/PushpanshuRanjanSingh/NearBY) is using it.**

Install Requirements

```python
pip3 install -r requirements.txt
```

## Some sort of problem during hosting it on [Heroku](https://dashboard.heroku.com/) ##

> **Problem Number - 1** 
```sh
 !     Error while running '$ python manage.py collectstatic --noinput'.
       See traceback above for details.
       You may need to update application code to resolve this error.
       Or, you can disable collectstatic for this application:
          $ heroku config:set DISABLE_COLLECTSTATIC=1
       https://devcenter.heroku.com/articles/django-assets
 !     Push rejected, failed to compile Python app.
 !     Push failed
```

**Solution**

Django won’t automatically create the target directory (STATIC_ROOT) that collectstatic uses, if it isn’t available. You may need to create this directory in your codebase, so it will be available when collectstatic is run. Git does not support empty file directories, so you will have to create a file inside that directory as well. So this is a file to complete rule.

Add this Line into settings.py > MIDDLEWARE
```python
'whitenoise.middleware.WhiteNoiseMiddleware',
```

Add this Line into settings.py (Buttom Line)
```python
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
```

Heroku Doesn't have Static File. So we need to create static folder inside your project folder. make sure that folder have atleast one file
<center>
<img src="https://i.loli.net/2020/10/10/H9RXfUITdiNnKVP.png" alt="Directory Structure" style="width:25%;" />
</center>



> **Problem Number - 2**

<center>
<p float="left">
<img src="https://i.loli.net/2020/10/10/ED13MzOkCLwqsHY.png" alt="Error on Terminal" width="50%" />
<img src="https://i.loli.net/2020/10/10/X3k4L9jShw8MQup.png" alt="Error on Web" width="33%" />
</p>
</center>

**Solution**

We don't have http server to run this instance so we need gunicorn.
> Add Procfile at root && write the below code

```r
release: python manage.py makemigrations --no-input
release: python manage.py migrate --no-input
# wsgi from settings.py
web: gunicorn nearbyauth.wsgi
```
