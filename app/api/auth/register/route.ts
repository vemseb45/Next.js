import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { z } from "zod";

// Validación 
const registerSchema = z.object({
  name: z.string().min(3), //minimo 3 caracteres en nombre
  email: z.string().email(),
  password: z.string().min(6), //minimo 6 caracteres en la contraseña
});

export async function POST(req: Request) {
  try {
    const body = await req.json();

    // Validar datos
    const data = registerSchema.parse(body);

    // Verificar si el usuario ya existe
    const userExists = await prisma.user.findUnique({
      where: { email: data.email },
    });

    if (userExists) {
      return NextResponse.json(
        { error: "Usuario ya existe" },
        { status: 400 }
      );
    }

    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(data.password, 10); //se coloca 10 ya que son las veces que bcrypt se va a ejecutar

    // Crear usuario
    const user = await prisma.user.create({
      data: {
        name: data.name,
        email: data.email,
        password: hashedPassword,
      },
    });

    return NextResponse.json({
        name: user.name,
        email: user.email,
    });
  } catch (error) {
    return NextResponse.json(
      { error: "Error en el registro" },
      { status: 500 }
    );
  }
}