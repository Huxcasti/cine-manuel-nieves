const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

const tickets = [];

/*
===========================
Servidor funcionando
===========================
*/

app.get("/", (req, res) => {
  res.json({
    status: "online",
    app: "Cine Teatro Manuel Nieves Quintero",
    version: "1.0"
  });
});

/*
===========================
Crear reservación
===========================
*/

app.post("/api/reservation", (req, res) => {

    const {
        movie,
        time,
        seats,
        total,
        customer
    } = req.body;

    const id = crypto.randomUUID();

    const qr = crypto.randomBytes(18).toString("hex");

    const reservation = {

        id,
        movie,
        time,
        seats,
        total,
        customer,

        paymentStatus:"pending",

        qr,

        created:new Date()

    };

    tickets.push(reservation);

    res.json(reservation);

});

/*
===========================
Simular pago
===========================
*/

app.post("/api/pay/:id",(req,res)=>{

    const ticket=tickets.find(
        t=>t.id===req.params.id
    );

    if(!ticket){

        return res.status(404).json({
            error:"No encontrado"
        });

    }

    ticket.paymentStatus="paid";

    res.json({

        success:true,

        ticket

    });

});

/*
===========================
Validar QR
===========================
*/

app.get("/api/qr/:code",(req,res)=>{

    const ticket=tickets.find(
        t=>t.qr===req.params.code
    );

    if(!ticket){

        return res.status(404).json({
            valid:false
        });

    }

    res.json({

        valid:true,

        ticket

    });

});

/*
===========================
Escanear QR
===========================
*/

app.post("/api/checkin/:code",(req,res)=>{

    const ticket=tickets.find(
        t=>t.qr===req.params.code
    );

    if(!ticket){

        return res.status(404).json({
            success:false
        });

    }

    if(ticket.used){

        return res.json({

            success:false,

            message:"Taquilla ya utilizada"

        });

    }

    ticket.used=true;

    ticket.checkin=new Date();

    res.json({

        success:true,

        message:"Entrada autorizada",

        ticket

    });

});

const PORT=process.env.PORT || 3000;

app.listen(PORT,()=>{

    console.log("Servidor iniciado en puerto "+PORT);

});
