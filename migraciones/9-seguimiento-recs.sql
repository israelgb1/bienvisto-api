-- Migración 9: recomendaciones aprobadas para los resúmenes quincenales (29 activas, 1 descartada).
-- Solo agrega una tabla; no toca datos existentes.
CREATE TABLE IF NOT EXISTS seguimiento_recs (
  id TEXT PRIMARY KEY,
  nivel TEXT NOT NULL CHECK (nivel IN ('bajo','medio','alto')),
  momento TEXT NOT NULL CHECK (momento IN ('todos','inicio','medio','cierre')),
  texto TEXT NOT NULL,
  activa INTEGER NOT NULL DEFAULT 1 CHECK (activa IN (0,1))
);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_1', 'alto', 'inicio', 'Buen ritmo. Ahora lo que más suma es responder todas las reseñas, incluidas las de pocas estrellas, con calma y sin discutir.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_10', 'alto', 'cierre', 'Si quieres apoyo para responder reseñas y cuidar tu ficha, el plan de arranque incluye respuestas redactadas y una sesión de 30 minutos.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_2', 'alto', 'todos', 'Si llega una reseña negativa, responde en público con respeto, reconoce lo que pasó y ofrece resolverlo por mensaje privado.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_3', 'alto', 'medio', 'Revisa las preguntas y respuestas de tu ficha. Agrega las 3 dudas que más te hacen tus clientes, con su respuesta.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_4', 'alto', 'medio', 'Con este volumen, vale la pena revisar las categorías y servicios de tu ficha. Que digan justo lo que la gente te busca.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_5', 'alto', 'todos', 'Comparte con tu equipo las reseñas buenas de la quincena y reconoce a quien se menciona. Mantiene el hábito de pedirlas.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_6', 'alto', 'inicio', 'Mantén al mismo responsable de pedir reseñas. Sostener el ritmo importa más que un pico de un fin de semana.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_7', 'alto', 'medio', 'Con permiso de quien la escribió, comparte una de tus mejores reseñas en tus redes.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_8', 'alto', 'todos', 'Revisa si otra zona de tu local necesita su propio display. Con este movimiento puede valer la pena.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_alto_9', 'alto', 'cierre', 'Ya tienes la base. El siguiente paso es convertir este ritmo en más clientes nuevos: cuéntame y vemos qué le falta a tu ficha.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_1', 'bajo', 'inicio', 'Prueba tu display con dos teléfonos distintos, uno iPhone y otro Android. Si alguno no abre la reseña, escríbeme y lo revisamos.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_10', 'bajo', 'cierre', 'Si quieres que revisemos tu ficha de Google y armemos un plan de reseñas a 30 días, el plan de arranque está pensado para este caso.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_2', 'bajo', 'todos', 'Colócalo donde el cliente tenga la mano libre: junto a la caja o sobre la mesa, no atrás del mostrador ni debajo de otros objetos.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_3', 'bajo', 'todos', 'Pide la reseña con la voz: al entregar el pedido o cobrar, di “si te gustó, nos ayudas con una reseña, solo acerca tu teléfono aquí”.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_4', 'bajo', 'todos', 'Elige el momento: pídela cuando el cliente ya está contento, al entregar el producto o terminar el servicio, no cuando tiene prisa por irse.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_5', 'bajo', 'inicio', 'Que una sola persona del equipo se encargue de mencionarlo en cada venta. Así no depende de que alguien se acuerde.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_6', 'bajo', 'medio', 'Pega junto al display una nota corta y legible: “Tu opinión nos ayuda a que más gente nos encuentre”. Que se vea desde donde el cliente espera.', 0);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_7', 'bajo', 'medio', 'Fíjate una meta pequeña: 3 reseñas por semana. Anota con una marca en un papel cuántas pides y cuántas llegan.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_8', 'bajo', 'todos', 'Revisa que el display esté limpio, sin reflejos ni metal pegado detrás del chip, y a la altura de los ojos o de la mano.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_bajo_9', 'bajo', 'cierre', 'Pocos escaneos suele arreglarse con un pequeño ajuste. Esta semana anota cuántas veces tu equipo menciona el display y cuéntame; te digo qué cambiar.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_1', 'medio', 'inicio', 'Ya te escanean con regularidad. Mira en qué días llegan menos y refuerza la petición justo esos días.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_10', 'medio', 'cierre', 'Si quieres dar el siguiente paso, el plan de arranque revisa tu ficha y arma un plan de reseñas a 30 días para sostener este ritmo.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_2', 'medio', 'todos', 'Responde las reseñas nuevas en un par de días. Se nota que alguien atiende y anima a otros a opinar.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_3', 'medio', 'todos', 'Al agradecer, usa el nombre de quien reseñó y menciona algo concreto de su visita. Una respuesta distinta a cada persona se ve más cuidada.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_4', 'medio', 'medio', 'Invita a quienes dejan reseña a subir una foto de su pedido o del lugar. Las fotos recientes hacen que tu ficha se vea viva.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_5', 'medio', 'inicio', 'Revisa tu ficha de Google: horario, teléfono, dirección y categoría. Una ficha completa y al día genera confianza.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_6', 'medio', 'medio', 'Que todo el equipo use una frase similar para pedir la reseña. Dile a tu gente cuál es y por qué la pides.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_7', 'medio', 'medio', 'Sube 3 fotos nuevas a tu ficha esta quincena: fachada, interior y tu producto más pedido.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_8', 'medio', 'todos', 'Identifica el día con más escaneos y pon a una persona atenta al display en ese horario.', 1);
INSERT OR IGNORE INTO seguimiento_recs (id, nivel, momento, texto, activa) VALUES ('r_medio_9', 'medio', 'cierre', 'Si tienes otra zona de atención, como barra, entrada o segundo mostrador, un segundo display ahí puede duplicar las oportunidades.', 1);
