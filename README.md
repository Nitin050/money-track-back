# money-track-back
-create virtual env
pip install virtualenv 
virtualenv env
source env/bin/activate

-install
pip install -r requirements.txt

-make migrations
python manage.py makemigrations

-runserver
python manage.py runserver