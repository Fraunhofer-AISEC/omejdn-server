# API

The Omejdn API consists of two parts:

- A user self-service API at */api/v1/user*
- An administrative API at */api/v1/config*

## User Selfservice API

Using this API requires an Access Token with scopes (in order of increasing access rights)
- omejdn:read,
- omejdn:write, or
- omejdn:admin

Every **GET** method requires at least omejdn:read,
while every other method requires at least omejdn:write.

#### Retrieving the current user

**GET** */api/v1/user*

Request payload: empty  
Success response: ```200 OK```  
Response payload:
```
{
  "username": String,
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
  "password": String
}
```

#### Updating the current user

**PUT** */api/v1/user*

Request payload:
```
{
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
}
```

Success response: ```204 No Content```  
Response payload: empty

#### Deleting the current user

**DELETE** */api/v1/user*

Request payload: empty
Success response: ```204 No Content```  
Response payload: empty

#### Changing the user's password

**PUT** */api/v1/user/password*

Request payload:
```
{
  "currentPassword": String
  "newPassword": String
}
```

Success response: ```204 No Content```  
Response payload: empty

#### Aquiring the user's provider

**GET** */api/v1/user/provider*

Request payload: empty  
Success response: ```200 OK```  
Response payload:
```
TBD
```


## Omejdn Admin API

### Clients

#### List clients

**GET** */api/v1/config/clients*

Request payload: empty  
Success response: ```200 OK```  
Response payload:
```
[
  {
    "client_id": String,
    "name": String,
    "allowed_scopes": Array<String>,
    "redirect_uri": String,
    "attributes": [
      {
        "key": String
        "value": String/Boolean
      },
      ...
    ]
  },
  ...
]
```

#### Overwrite client list

**PUT** */api/v1/config/clients*

Request payload:
```
[
  {
    "client_id": String,
    "name": String,
    "allowed_scopes": Array<String>,
    "redirect_uri": String,
    "attributes": [
      {
        "key": String
        "value": String/Boolean
      },
      ...
    ]
  },
  ...
]
```

Success response: ```204 No Content```  
Response payload: empty

#### Add client

**POST** */api/v1/config/clients*

Request payload:
```
{
  "client_id": String,
  "name": String,
  "allowed_scopes": Array<String>,
  "redirect_uri": String,
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
}
```
Success response: ```201 Created```
Response payload: empty  


#### Show client

**GET** */api/v1/config/clients/:client_id*

Request payload: empty  
Success response: ```200 OK```  
Response payload:
```
{
  "client_id": String,
  "name": String,
  "allowed_scopes": Array<String>,
  "redirect_uri": String,
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
}
```

#### Update client

**PUT** */api/v1/config/clients/:client_id*

Request payload:
```
{
  "name": String,
  "allowed_scopes": Array<String>,
  "redirect_uri": String,
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
}
```

Note: You may omitt some keys. Omitted keys remain unchanged.

Success response: ```204 No Content```  
Response payload: empty

#### Delete client

**DELETE** */api/v1/config/clients/:client_id*

Request payload: empty   
Success response: ```204 No Content```
Response payload: empty   

### Client Certificates

Please Note that currently each client can only have a single certificate.

#### Get a clients certificate

**GET** */api/v1/config/clients/:client_id/keys*

Request payload: empty
Success respnse: ```200 OK```    
Response payload:

```
{
  "certificate": String
}
```


#### Update a clients certificate

**PUT** */api/v1/config/clients/:client_id/keys*

Request payload: 

```
{
  "certificate": String
}
```
Success response: ```204 No Content```     
Response payload: empty



#### Add a clients certificate

**POST** */api/v1/config/clients/:client_id/keys*

Request payload: 

```
{
  "certificate": String
}
```
Success response: ```201 Created ```     
Response payload: empty



#### Delete a clients certificate

**DELETE** */api/v1/config/clients/:client_id/keys*

Request payload: empty
Success response: ```204 No Content```
Response payload: empty


### Users


#### List users

**GET** */api/v1/config/users*

Request payload: empty
Success response: ```200 OK```
Response payload:    
```
[
  {
    "username": String,
    "attributes": [
      {
        "key": String
        "value": String/Boolean
      },
      ...
    ]
    "password": String
  },
  ...
]
```


#### Adding a user

**POST** */api/v1/config/users*

Request payload:
```
{
  "username": String,
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
  "password": String
}
```

#### Retrieving a specific user

**GET** */api/v1/config/users/:username*

Request payload: empty
Success response: ```200 OK```
Response payload:
```
{
  "username": String,
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
  "password": String
}
```

Note: The password should be in the bcrypt format.
Alternatively consider changing the password after creating the user.

#### Updating a specific user

**PUT** */api/v1/config/users/:username*

Request payload:
```
{
  "attributes": [
    {
      "key": String
      "value": String/Boolean
    },
    ...
  ]
}
```

Success response: ```204 No Content```  
Response payload: empty

#### Deleting a specific user

**DELETE** */api/v1/config/users/:username*

Request payload: empty
Success response: ```204 No Content```  
Response payload: empty

#### Changing the user's password

**PUT** */api/v1/user/password*

Request payload:
```
{
  "newPassword": String
}
```

Success response: ```204 No Content```  
Response payload: empty

### Providers

TODO: document.
If in doubt, edit the oauth_providers file as described below

### Config

The Omejdn config files can be retrieved and overwritten in a JSON format.
The format is exactly as in those files, they are simply translated between YAML and JSON

```:file``` can take the possible values:
- **omejdn** the base configuration file
- **user_backend** the user backend configuration file
- **webfinger** the webfinger configuration file
- **oauth_providers** the oauth_providers configuration file


#### Show config

**GET** */api/v1/config/:file*

Request payload: empty
Success response: ```200 OK ```    
Response payload: _file dependent_


#### Update config

**PUT** */api/v1/config/:file*

Request payload: _file dependent_
Success response: ```200 OK ```    
Response payload: empty

