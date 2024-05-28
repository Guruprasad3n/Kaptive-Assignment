const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

const authenticate = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).send({ error: 'Not authenticated' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user) {
      throw new Error();
    }
    req.user = user;
    next();
  } catch (err) {
    res.status(401).send({ error: 'Not authenticated' });
  }
};

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 8);
  try {
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
    res.status(201).send({ user });
  } catch (err) {
    res.status(400).send(err);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).send({ error: 'Invalid login credentials' });
  }
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.send({ user, token });
});


app.post('/transactions', authenticate, async (req, res) => {
  const { amount, type, categoryId, date } = req.body;
  const transaction = await prisma.transaction.create({
    data: {
      userId: req.user.id,
      amount,
      type,
      categoryId,
      date: new Date(date),
    },
  });
  res.status(201).send(transaction);
});

app.get('/transactions', authenticate, async (req, res) => {
  const transactions = await prisma.transaction.findMany({
    where: { userId: req.user.id },
    include: { Category: true },
  });
  res.send(transactions);
});

app.put('/transactions/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { amount, type, categoryId, date } = req.body;
  const transaction = await prisma.transaction.update({
    where: { id: id },
    data: { amount, type, categoryId, date: new Date(date) },
  });
  res.send(transaction);
});

app.delete('/transactions/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  await prisma.transaction.delete({ where: { id: id } });
  res.status(204).send();
});

app.post('/budgets', authenticate, async (req, res) => {
  const { amount, month, year } = req.body;
  const budget = await prisma.budget.create({
    data: {
      userId: req.user.id,
      amount,
      month,
      year,
    },
  });
  res.status(201).send(budget);
});

app.get('/budgets', authenticate, async (req, res) => {
  const budgets = await prisma.budget.findMany({
    where: { userId: req.user.id },
  });
  res.send(budgets);
});

app.get('/reports/:month/:year', authenticate, async (req, res) => {
  const { month, year } = req.params;
  const transactions = await prisma.transaction.findMany({
    where: {
      userId: req.user.id,
      date: {
        gte: new Date(year, month - 1, 1),
        lt: new Date(year, month, 1),
      },
    },
  });
  const income = transactions.filter(t => t.type === 'income').reduce((acc, t) => acc + t.amount, 0);
  const expenses = transactions.filter(t => t.type === 'expense').reduce((acc, t) => acc + t.amount, 0);
  res.send({ income, expenses, balance: income - expenses });
});

app.get('/expenses/:categoryId', authenticate, async (req, res) => {
  const { categoryId } = req.params;
  const expenses = await prisma.transaction.findMany({
    where: {
      userId: req.user.id,
      categoryId: categoryId,
      type: 'expense',
    },
  });
  res.send(expenses);
});


const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
