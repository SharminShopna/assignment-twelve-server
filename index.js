const express = require('express');
const app = express();
const cors = require('cors');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const admin = require("firebase-admin");
const firebaseAdminAccount = require("./firebaseAdmin.json");
admin.initializeApp({
  credential: admin.credential.cert(firebaseAdminAccount),
  databaseURL: process.env.REALTIME_DATABASE_URL_FIREBASE,
});
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const nodemailer = require("nodemailer");
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY)
const port = process.env.PORT || 5000;

// Middleware to check JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extract token
  if (!token) {
    return res.status(401).send({ message: 'Unauthorized access' }); // No token found
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(401).send({ message: 'Unauthorized access' }); 
    }
    req.user = decoded; 
    next();
  });
};


// CORS Configuration
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:5174',
      'https://assignment-twelve-6bd21.web.app',
      'https://assignment-twelve-6bd21.firebaseapp.com',
      // Replace production URL
    ];

    // Allow requests with no origin
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionSuccessStatus: 200,
};

// Middleware setup
app.use(cors(corsOptions));
app.use(express.json());
app.use(morgan('dev'));


// send email using nodemailer
const sendEmail = (emailAddress, emailData) => {
  // create transporter
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for port 465, false for other ports
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });
  // verify connection 
  transporter.verify((error, success) => {
    if (error) {
      console.log(error)
    } else {
      console.log('Transporter is ready to email', success)
    }
  })
  // transporter.sendMail()
  const mailBody = {
    from: process.env.NODEMAILER_USER, // sender address
    to: emailAddress, // list of receivers
    subject: emailData?.subject, // Subject line
    // text: emailData?.message, // plain text body
    html: `<p>${emailData?.message}</p>`, // html body
  }
  // send Email
  transporter.sendMail(mailBody, (error, info) => {
    if (error) {
      console.log(error)
    } else {
      // console.log(info)
      console.log('Email Send: ' + info?.response)
    }
  })
}




// MongoDB setup

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.emc8p.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

async function run() {
  try {
    const propertyCollection = client.db('houseBoxDb').collection('property');
    const usersCollection = client.db('houseBoxDb').collection('users');
    const wishlistCollection = client.db('houseBoxDb').collection('wishlist');
    const offersCollection = client.db('houseBoxDb').collection('offers');
    const reviewsCollection = client.db('houseBoxDb').collection('reviews');
    const orderCollection = client.db('houseBoxDb').collection('orders');
    const advertisementCollection = client.db('houseBoxDb').collection('advertisements');

    // verify admin middleware
    const verifyAdmin = async (req, res, next) => {
      //  console.log('data verify token admin verified', req.user?.email)
      const email = req.user?.email
      const query = { email }
      const result = await usersCollection.findOne(query)
      if (!result || result?.role !== 'admin')
        return res.status(403).send({ message: 'Forbidden Access! Admin Only Actions!' })

      next()
    }

    // verify agent middleware
    const verifyAgent = async (req, res, next) => {
      //  console.log('data verify token agent verified', req.user?.email)
      const email = req.user?.email
      const query = { email }
      const result = await usersCollection.findOne(query)
      if (!result || result?.role !== 'agent')
        return res.status(403).send({ message: 'Forbidden Access! Agent Only Actions!' })

      next()
    }





    // Generate JWT token for login
    app.post('/jwt', (req, res) => {
      const email = req.body.email;
      if (!email) {
        return res.status(400).send({ message: 'Email is required to generate a token' });
      }

      const token = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '365d' });
      console.log(`Generated Token: ${token}`);
      res.send({ token });
    });



    // Get all properties
    app.get('/adv-properties', async (req, res) => {
      const result = await advertisementCollection.find().limit(8).toArray();
      res.send(result);
    });
 
    // All properties with search and sort functionality
    app.get('/all-properties', async (req, res) => {
      try {
        const { location, sort } = req.query;
        const query = {};
    
        if (location) {
          query.location = { $regex: location, $options: 'i' };
        }
    
        let sortOption = {};
        if (sort === 'asc') {
          sortOption = { minPrice: 1 }; 
        } else if (sort === 'desc') {
          sortOption = { minPrice: -1 }; 
        }
    
        const result = await propertyCollection.find(query).sort(sortOption).toArray();
        res.send(result);
      } catch (error) {
        console.error('Error fetching properties:', error);
        res.status(500).send({ message: 'Failed to fetch properties' });
      }
    });
    




    // get a properties by id
    app.get('/properties/:id', async (req, res) => {
      console.log('API hit with ID:', req.params.id);
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await propertyCollection.findOne(query)
      console.log('Query Result:', result);
      res.send(result)
    })

    // Get wishlist for a user
    app.get('/wishlist/:userId', verifyToken, async (req, res) => {
      const userId = req.params.userId;
      const wishlistItems = await wishlistCollection.find({ userId }).toArray();

      if (!wishlistItems.length) {
        return res.status(404).send({ message: 'No wishlist items found for this user' });
      }

      const properties = await Promise.all(
        wishlistItems.map(async (item) => {
          const property = await propertyCollection.findOne({ _id: new ObjectId(item.propertyId) });
          return { ...item, ...property };
        })
      );

      res.send(properties);
    });


    // Get user details from JWT token
    // app.get('/me', verifyToken, async (req, res) => {
    //   const email = req.user.email;

    //   try {
    //     // Fetch user details from the database
    //     const user = await usersCollection.findOne({ email });
    //     if (!user) {
    //       return res.status(404).send({ message: 'User not found' });
    //     }

    //     res.send(user);
    //   } catch (error) {
    //     console.error(error);
    //     res.status(500).send({ message: 'Failed to fetch user details' });
    //   }
    // });

    // gat all user data
    app.get('/all-users/:email', verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email
      const query = { email: { $ne: email } }
      const result = await usersCollection.find(query).toArray()
      res.send(result)
    })

    // update a user role and status
    app.patch('/user/role/:email', verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const { role } = req.body;
      console.log({ email, role })
      try {
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: 'User not found' });
        }
        if (user.role === role) {
          return res.status(400).send({ message: 'Role is already the same' });
        }
        const filter = { email };
        const updateDoc = {
          $set: { role, status: 'verified' },
        };

        const result = await usersCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Failed to update role' });
      }
    });


    // get user role
    app.get('/users/role/:email', async (req, res) => {
      const email = req.params.email
      const result = await usersCollection.findOne({ email })
      res.send({ role: result?.role })
    })

    // Save offer to the database
    app.post('/offer', verifyToken, async (req, res) => {
      const offerInfo = req.body
      console.log(offerInfo)
      const result = await offersCollection.insertOne(offerInfo)
      // send Email
      if (result?.insertedId) {

        // To Buyer
        sendEmail(offerInfo?.buyer?.email, {
          subject: 'Order Successful',
          message: `You've placed an order successfully. Transaction Id: ${result?.insertedId}`,
        })
        // To agent
        sendEmail(offerInfo?.agent, {
          subject: 'Hurray!, You have an order to process',
          message: `Get the property ready for ${offerInfo?.buyer?.name}`,
        })
      }
      res.send(result)
    })

    // Manage Offer quantity
    app.patch('/property/quantity/:id', verifyToken, async (req, res) => {
      const id = req.params.id
      const { quantityToUpdate, status } = req.body
      const filter = { _id: new ObjectId(id) }
      let updateDoc = {
        $inc: { quantity: -quantityToUpdate },
      }
      if (status === 'increase') {
        updateDoc = {
          $inc: { quantity: quantityToUpdate },
        }
      }
      const result = await propertyCollection.updateOne(filter, updateDoc)
      res.send(result)
    })

    //  get all orders for a specific customer
    app.get('/buyer-orders/:email', verifyToken, async (req, res) => {
      const email = req.params.email
      const result = await offersCollection.aggregate([
        {
          $match: { 'buyer.email': email },
        },
        {
          $addFields: {
            propertyId: { $toObjectId: '$propertyId' },
          },
        },
        {
          $lookup: {
            from: 'property',
            localField: 'propertyId',
            foreignField: '_id',
            as: 'property'
          },
        },
        { $unwind: '$property' },
        {
          $addFields: {
            agentName: '$property.agent.name',
            image: '$property.image',
          },
        },
        {
          $project: {
            property: 0,
          },
        },
      ]).toArray()
      res.send(result)
    })


    // get all order for a specific agent
    app.get('/agent-orders/:email', verifyToken, verifyAgent, async (req, res) => {
      const email = req.params.email
      const query = { 'agent': email }
      const result = await offersCollection.find(query).toArray()
      res.send(result)
    })

    // update a order status
    app.patch('/orders/:id', verifyToken, verifyAgent, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;
      console.log({ id, status })
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: { status },
      };

      const result = await offersCollection.updateOne(filter, updateDoc);
      res.send(result);

    });



    // cancel/delete an order
    app.delete('/orders/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const order = await offersCollection.findOne(query);
      if (!order) {
        return res.status(404).send({ message: 'Order not found' });
      }
      if (order.status === 'Accepted') {
        return res.status(409).send({ message: 'Cannot cancel the offer as it has already been accepted' });
      }
      const result = await offersCollection.deleteOne(query);
      res.send({ message: 'Order deleted successfully', result });
    });





    // Remove property from wishlist
    app.delete('/wishlist/:userId/:propertyId', verifyToken, async (req, res) => {
      const { userId, propertyId } = req.params;
      // console.log({userId, propertyId})
      const result = await wishlistCollection.deleteOne({ userId, propertyId });
      // console.log(result)
      res.send(result);
    });





    // Add property to wishlist
    app.post('/wishlist', verifyToken, async (req, res) => {
      const { userId, propertyId, image, title, location, minPrice, maxPrice, status } = req.body;

      const existing = await wishlistCollection.findOne({ userId, propertyId });
      if (existing) {
        return res.status(400).send({ message: 'Property already in wishlist' });
      }

      const result = await wishlistCollection.insertOne({
        userId,
        propertyId,
        image,
        title,
        location,
        minPrice,
        maxPrice,
        status,
        timestamp: Date.now(),
      });

      res.send(result);
    });




    // Save or update user data
    app.post('/users/:email', async (req, res) => {
      sendEmail()
      const email = req.params.email;
      const user = req.body;
      const isExist = await usersCollection.findOne({ email });

      if (isExist) {
        return res.send(isExist);
      }

      const result = await usersCollection.insertOne({
        ...user,
        role: 'customer',
        image: user.image || 'https://i.ibb.co.com/5Y5gXFF/IMG-4292.jpg',
        timestamp: Date.now(),
      });
      res.send(result);
    });

    // manage user status and role
    app.patch('/users/:email', verifyToken, async (req, res) => {
      const email = req.params.email
      const query = { email }
      const user = await usersCollection.findOne(query)
      if (!user || user?.status === 'Requested') return res.status(400).send('You have already requested, wait for some time.')

      const updateDoc = {
        $set: {
          status: 'Request',

        },
      }
      const result = await usersCollection.updateOne(query, updateDoc)
      console.log(result)
      res.send(result)
    })

    // user status related get
    app.get('/users/status/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await usersCollection.findOne(query);

      if (!user) return res.status(404).send({ status: "Not Found" });

      res.send({ status: user.status || "None" });
    });



    // Save property data in DB (protected route)
    app.post('/property', verifyToken, verifyAgent, async (req, res) => {
      const property = req.body;
      const result = await propertyCollection.insertOne(property);
      res.send(result);
    });


    // Get properties for an agent
    app.get('/propertySection', verifyToken, verifyAgent, async (req, res) => {
      const agentEmail = req.user.email;
      const agentProperties = await propertyCollection.find({ "agent.email": agentEmail }).toArray();
      res.send(agentProperties);
    });



    // Update property details
    app.patch('/properties/:id', verifyToken, async (req, res) => {
      const propertyId = req.params.id;
      const { title, location, minPrice, maxPrice, image } = req.body;

      // Update property in the database
      const result = await propertyCollection.updateOne(
        { _id: new ObjectId(propertyId) },
        { $set: { title, location, minPrice, maxPrice, image } }
      );

      if (result.modifiedCount === 0) {
        return res.status(404).send({ message: 'Property not found' });
      }

      res.send({ message: 'Property updated successfully' });
    });


    // Delete property (Agent only)
    app.delete('/properties/:id', verifyToken, verifyAgent, async (req, res) => {
      const propertyId = req.params.id;
      const property = await propertyCollection.findOne({ _id: new ObjectId(propertyId) });

      if (!property || property.agent.email !== req.user.email) {
        return res.status(403).send({ message: 'You can only delete your own properties' });
      }

      const result = await propertyCollection.deleteOne({ _id: new ObjectId(propertyId) });
      res.send({ message: 'Property deleted successfully', result });
    });


    app.post('/reviews', verifyToken, async (req, res) => {
      try {
        const body = req.body;
        body.time = new Date().toISOString();
        const result = await reviewsCollection.insertOne(body);

        res.send(result);
      } catch (error) {
        console.error('Error inserting review:', error);
        res.status(500).send({ error: 'Failed to insert review' });
      }
    });


    // Get all reviews for a specific property with property details
    app.get('/reviews/:propertyId', async (req, res) => {
      const { propertyId } = req.params;

      try {
        const reviewsWithProperty = await reviewsCollection.aggregate([
          {
            $match: { propertyId },
          },
          {
            $lookup: {
              from: 'property',
              localField: 'propertyId',
              foreignField: '_id',
              as: 'propertyDetails',
            },
          },
          {
            $unwind: '$propertyDetails',
          },
        ]).toArray();

        res.send(reviewsWithProperty);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Failed to fetch reviews with property details' });
      }
    });



    // Get reviews by a specific user
    app.get('/my-reviews/:email', verifyToken, async (req, res) => {
      const { email } = req.params;
      const reviews = await reviewsCollection.find({ email }).toArray();
      res.send(reviews);
    });


    // Delete a review by ID
    app.delete('/reviews/:id', verifyToken, async (req, res) => {
      const { id } = req.params;
      const review = await reviewsCollection.findOne({ _id: new ObjectId(id) });

      if (review.email !== req.user.email) {
        return res.status(403).send({ message: 'You can only delete your own reviews' });
      }

      const result = await reviewsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // Get all offers for properties added by the agent

    // API to get all offers

    app.get('/agent-offers', verifyToken, async (req, res) => {
      const offers = await offersCollection
        .aggregate([
          {
            $addFields: {
              propertyIdAsObjectId: { $toObjectId: '$propertyId' },
            },
          },
          {
            $lookup: {
              from: 'property',
              localField: 'propertyIdAsObjectId',
              foreignField: '_id',
              as: 'property',
            },
          },
        ])
        .toArray();
      res.send(offers)
    });


    // API to accept/reject an offer
    app.patch('/agent-offers/:id', verifyToken, async (req, res) => {
      const offerId = req.params.id;
      const { status } = req.body;

      if (!['accepted', 'rejected'].includes(status)) {
        return res.status(400).send({ message: 'Invalid status value' });
      }

      const offer = await offersCollection.findOne({ _id: new ObjectId(offerId) });
      if (!offer) {
        return res.status(404).send({ message: 'Offer not found' });
      }

      if (status === 'accepted') {
        await offersCollection.updateMany(
          { propertyId: offer.propertyId, _id: { $ne: offer._id } },
          { $set: { status: 'rejected' } }
        );
      }

      const result = await offersCollection.updateOne(
        { _id: new ObjectId(offerId) },
        { $set: { status } }
      );
      res.send(result);
    });


    // Admin related
    //  All Property get data
    app.get('/propertiesData', async (req, res) => {
      const result = await propertyCollection.find().toArray();
      res.send(result);
    });

    // Verify property
    app.patch('/properties-verify/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = { $set: { status: 'verified' } };

      const result = await propertyCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Reject property
    app.patch('/properties-reject/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = { $set: { status: 'rejected' } };

      const result = await propertyCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // all review data
    app.get('/reviews', async (req, res) => {
      const result = await reviewsCollection.find().toArray();
      res.send(result);
    });

    // Delete review by Admin
    app.delete('/admin-reviews/:id', verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      const result = await reviewsCollection.deleteOne({ _id: new ObjectId(id) });

      if (result.deletedCount === 0) {
        return res.status(404).send({ message: 'Review not found' });
      }

      res.send({ message: 'Review deleted successfully' });
    });





    // common section review
    // Get Latest Reviews with Reviewer Info (Name, Image) and Property Title

    app.get('/latest-reviews', async (req, res) => {
      const reviews = await reviewsCollection.aggregate([
        {
          $sort: {
            time: -1
          }
        },
        {
          $limit: 4
        },

        {
          $lookup: {
            from: 'users',
            localField: 'email',
            foreignField: 'email',
            as: 'userDetails'
          }
        },
        {
          $unwind: '$userDetails'
        },
        {
          $addFields: {
            'name': '$userDetails.name',
            'image': '$userDetails.image'
          }
        },
        {
          $project: {
            userDetails: 0,
          }
        }
      ]).toArray();

      res.send(reviews);
    });

    // create payment intent
    app.post('/create-payment-intent', verifyToken, async (req, res) => {
      const { price } = req.body;
      const amount = parseInt(price * 100);
      console.log(amount, 'amount inside the intent')
      const { client_secret } = await stripe.paymentIntents.create({
        amount: amount,
        currency: 'usd',
        automatic_payment_methods: {
          enabled: true,
        }
      });
      //  console.log(paymentIntent)
      res.send({ clientSecret: client_secret })
    })


    // Save offer to the database
    app.post('/order', verifyToken, async (req, res) => {
      const offerInfo = req.body
      console.log(offerInfo)
      const result = await orderCollection.insertOne(offerInfo)
      // send Email
      if (result?.insertedId) {

        // To Buyer
        sendEmail(offerInfo?.buyer?.email, {
          subject: 'Order Successful',
          message: `You've placed an order successfully. Transaction Id: ${result?.insertedId}`,
        })
        // To agent
        sendEmail(offerInfo?.agent, {
          subject: 'Hurray!, You have an order to process',
          message: `Get the property ready for ${offerInfo?.buyer?.name}`,
        })
      }
      res.send(result)
    })

    // Fetch all admin-verified properties
    app.get('/admin-verified-properties',verifyToken, verifyAdmin, async (req, res) => {
      try {
        const verifiedProperties = await propertyCollection
          .find({ status: 'verified' })
          .toArray();
        res.send(verifiedProperties);
      } catch (error) {
        console.error('Error fetching verified properties:', error);
        res.status(500).send({ message: 'Failed to fetch properties' });
      }
    });


    
    // Add property to the advertisements collection
    app.post('/advertise-property', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { propertyId } = req.body;
        const property = await propertyCollection.findOne({ _id: new ObjectId(propertyId) });
        if (!property) {
          return res.status(404).send({ message: 'Property not found' });
        }

        // Check if the property is already advertised
        const advertised = await advertisementCollection.findOne({ _id: property._id });
        if (advertised) {
          return res.status(400).send({ message: 'Property is already advertised' });
        }
        const result = await advertisementCollection.insertOne(property);
        res.send({ success: true, message: 'Property advertised successfully', result });
      } catch (error) {
        console.error('Error advertising property:', error);
        res.status(500).send({ message: 'Failed to advertise property' });
      }
    });
  

    // agent total sold amount
    app.get('/agent-stat', verifyToken, verifyAgent, async(req,res)=>{
      // get total Property
      const totalProperty = await propertyCollection.estimatedDocumentCount()
       const totalOrder = await orderCollection.estimatedDocumentCount()
      const allOrder = await orderCollection.find().toArray()
      const totalPrice = allOrder.reduce((sum, order)=> sum + order.price,0)
      //  console.log({totalPrice, totalOrder})
      res.send({ totalProperty, totalPrice, totalOrder})
    })


    //firebase delete, admin

    app.post("/deleteUser", async (req, res) => {
      const { email } = req.body;
      console.log("Received email for deletion:", email);
    
      if (!email) {
        return res.status(400).json({ error: "Email is required" });
      }
    
      try {
        console.log("Fetching user from Firebase Authentication...");
        const userRecord = await admin.auth().getUserByEmail(email);
        const uid = userRecord.uid;
        console.log("User UID found:", uid);
    
        console.log("Deleting user from MongoDB...");
        const deleteUser = await usersCollection.deleteOne({ email: email });
        console.log("Delete result from MongoDB:", deleteUser);
    
        if (deleteUser.deletedCount === 0) {
          return res.status(404).json({ error: `User with email ${email} not found in the database.` });
        }
    
        console.log("Deleting user from Firebase Authentication...");
        await admin.auth().deleteUser(uid);
        console.log("User deleted from Firebase Authentication.");
    
        console.log("Deleting user from Firestore...");
        const userRef = admin.firestore().collection("users").doc(uid);
        const doc = await userRef.get();
        if (doc.exists) {
          await userRef.delete();
          console.log("User deleted from Firestore.");
        } else {
          console.log("No user found in Firestore for UID:", uid);
        }
    
        return res.status(200).json({
          message: `User with email ${email} deleted successfully.`,
        });
      } catch (error) {
        console.error("Error deleting user:", error.message, error.stack);
        return res.status(500).json({ error: "Failed to delete user.", details: error.message });
      }
    });




    // Connect to MongoDB
    // await client.connect();
    // await client.db('admin').command({ ping: 1 });
    // console.log('MongoDB connected successfully!');
  } finally {
    // Do not close client here
  }
}

run().catch(console.error);

// Default route
app.get('/', (req, res) => {
  res.send('Real Estate Platform server is running');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});