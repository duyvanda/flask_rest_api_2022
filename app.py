from flask import Flask, request
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, JWTManager
from hmac import compare_digest

from security import username_table, userid_table

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True # To allow flask propagating exception even if debug is set to false on app
app.config["JWT_SECRET_KEY"] = "123phanam"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False  # Change this!
api = Api(app)

# jwt = JWT(app, authenticate, identity)
# jwt.JWT_AUTH_HEADER_PREFIX = "JWT"

jwt = JWTManager(app)

items = [{'name': "Duy", 'price': 1.5}]

class Item(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('price',
        type=float,
        required=True,
        help="This field cannot be left blank!"
    )

    @jwt_required()
    def get(self, name):
        return {'item': next(filter(lambda x: x['name'] == name, items), None)}

    def post(self, name):
        if next(filter(lambda x: x['name'] == name, items), None) is not None:
            return {'message': "An item with name '{}' already exists.".format(name)}

        data = Item.parser.parse_args()

        item = {'name': name, 'price': data['price']}
        items.append(item)
        return item

    @jwt_required()
    def delete(self, name):
        global items
        items = list(filter(lambda x: x['name'] != name, items))
        return {'message': 'Item deleted'}

    @jwt_required()
    def put(self, name):
        data = Item.parser.parse_args()
        # Once again, print something not in the args to verify everything works
        item = next(filter(lambda x: x['name'] == name, items), None)
        if item is None:
            item = {'name': name, 'price': data['price']}
            items.append(item)
        else:
            item.update(data)
        return item


class ItemList(Resource):

    @jwt_required()
    def get(self):
        return {'items': items}


_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username',
                          type=str,
                          required=True,
                          help="This field cannot be blank."
                          )
_user_parser.add_argument('password',
                          type=str,
                          required=True,
                          help="This field cannot be blank."
                          )

class UserLogin(Resource):
    def post(self):
        data = _user_parser.parse_args()

        user = username_table.get(data['username'], None)

        # this is what the `authenticate()` function did in security.py
        if user and compare_digest(user.password, data['password']):
            # identity= is what the identity() function did in security.py—now stored in the JWT
            access_token = create_access_token(identity=user.id, fresh=True) 
            refresh_token = create_refresh_token(user.id)
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200

        return {"message": "Invalid Credentials!"}, 401

api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(UserLogin, '/login')

if __name__ == '__main__':
    app.run(debug=True)  # important to mention debug=True