import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')

app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch {}

  next() // -> seguir a la siguiente ruta o middleware
})

app.get('/', (req, res) => { 
  const { user } = req.session
  res.render('index', user)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body 

  try { 
    const user = await UserRepository.login({ username, password })
    const token = jwt.sing(
      { id: user._id, username: user.username },
       SECRET_JWT_KEY, 
       {
      expiresIn: '1h'
    })
    res
    .cookie('access_token', token, {
      htttpOnly: true, // la cookie solo se puede acceder en el servidor
      secure: process.env.NODE_ENV === 'production', // la cookie solo e puede acceder en https
      sameSite: 'strict', // la cookie solo se puede acceder en el mismo dominio 
      maxAge: 1000 * 60 * 60 // la cookie tiene un tiempo de validez de 1 hora
    })
    .send({ user, token })
  } catch (error) { 
    res.status(401).send(error.message)
  }
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body // ????
  console.log({ username, password })

  try {
    const id = await UserRepository.create({ username, password })
    res.send({ id })
  } catch (error) {
    // NORMALMENTE NO ES BUENA IDEA MANDAR EL ERROR
    res.status(400).send(error.message)
  }
})

app.post('/logout', (req, res) => {
  res
  .clearCookie('access_token')
  .json({ message: 'Logout successful' })
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Access not authorized')
  res.render('protected', user) // { _id,username }
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
