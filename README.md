# udacity-catalog

# Project Item Catalog Overview
Develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. 
Registered users will have the ability to post, edit and delete their own items.

This application will display a number vehicle makes (categories), and allow the users to browse wehcles of each maker.
Logged in users can create additional makes and vehicles and edit any entrhyies they created.

# Project Display Examples

###### Sample Makes **Categories**
![GitHub Logo](/screenshots/catalog.png)

###### Sample Makes **Categories**
![GitHub Logo](/screenshots/Categories2.png)

###### Sample Vehicle **Item**
![GitHub Logo](/screenshots/VehicleItems.png)

## Getting Started

### Prerequisites

1. Install Vagrant and VirtualBox
2. Clone the fullstack-nanodegree-vm
3. Launch the Vagrant VM (vagrant up)
4. Write your Flask application locally in the vagrant/catalog directory (which will automatically be synced to /vagrant/catalog within the VM).
5. Run python3 database_setup.py,to setup database.
6. Run your application within the VM (python /vagrant/catalog/**application_pep8.py**)
7. Access and test your application by visiting http://localhost:8000 locally

You can find the link to the fullstack-nanodegree-vm here: http://github.com/udacity/fullstack-nanodegree-vm

## Demo data

The applicatin comes with a data base with two categories and two cars created.
The applicatin has the  abitiy to create REad update DElete categoies and items you create.

Some the front end does not function, non-funcitoning buttons are diabled.

##  JSON API data

All vehicles base on make id @app.route('/maker/<int:maker_id>/transportation/JSON')
All vehicle makes in the database: @app.route('/maker/JSON') 
All vehicles in the database: @app.route('/transportation/JSON')

## Extranal Sources
Udacity Fullstack for boilerplate CRUD and facebooklogin
MBD Material bootstrap for front end
unite gallery for image gallery

# Known Issues

## Pep8
A few long urls were left in as I could not pep8 them

## All cars must Automatic
In the add edit item forms the check box for automatic engine is throwing an error is not selected - still a python nube - i'll try fix this tonight.



## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* udacity rocks.
