var  jwt = require('jsonwebtoken');
var config = require('./config');


function verifyToken(req, res, next) {
  var token = req.headers['x-access-token'];
  if(!token)
    return res.status(403).send({success: false, message:  'no0 token'});

  jwt.verify(token, config.secret, function (err, decoded) {
    if (err)
      return res.status(500).send({success: false, message:'failed to auth token'});

    // if good going
    req.email = decoded.email;
    next();
  });
}
  module.exports = verifyToken;
