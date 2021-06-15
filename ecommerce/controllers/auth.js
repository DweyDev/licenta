const User = require('../models/User')
const { Order } = require('../models/Order')
const { errorHandler } = require('../helpers/dbErrorHandler')

const jwt = require('jsonwebtoken') // generate signed in token
const expressJwt = require('express-jwt') // auth check

exports.signup = (req, res) => {
  const user = new User(req.body)
  user.save((err, user) => {
    if (err) {
      return res.status(400).json({
        err: errorHandler(err)
      })
    }
    user.salt = undefined
    user.hashed_password = undefined
    res.json({
      user
    })
  })
}

exports.signin = (req, res) => {
  const { email, password } = req.body
  User.findOne({
    email
  }).then((user, err) => {
    if (!user || err) {
      return res.status(400).json({
        err: 'User do not exists'
      })
    } 
    if (!user.authenticate(password)) {
      return res.status(401).json({
        error: 'Email and password does not match'
      })
    }
    const token = jwt.sign({id: user.id}, process.env.JWT_SECRET)
    res.cookie('t', token, {expire: new Date() + 9999})
    const { id, name, email, role } = user
    return res.json({token, user: {id, email, name, role}})
  })
}

exports.signout = (req, res) => {
  res.clearCookie('t')
  res.json({
    message: 'Signed out'
  })
}

exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET,
  userProperty: "auth",
  algorithms: ["HS256"]
})

exports.isAuth = (req, res, next) => {
  let user = req.profile && req.auth && req.profile.id === req.auth.id
  if (!user) {
    res.status(403).json({
      error: 'Access denied'
    })
    return null
  }
  next()
}

exports.isAdmin = (req, res, next) => {
  if (req.profile.role === 0) {
    res.status(403).json({
      error: 'Admin access only'
    })
    return null
  }

  next()
}