// /api/_stripe.js
const Stripe = require('stripe');
if(!process.env.STRIPE_SECRET_KEY){
  throw new Error('Falta STRIPE_SECRET_KEY en variables de entorno');
}
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });
module.exports = { stripe };
