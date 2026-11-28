/**
 * Timeline of the welcome scene, in seconds: a boat sails in, "phishes" the cards
 * out of the sea one after another and sails away. Pure, so it can be tested;
 * components/welcome/WelcomeScene.jsx draws it.
 */
export const SCENE_SECONDS = 5.6;
const ARRIVE = 1.6;      // the boat reaches the middle
const STAGGER = 0.45;    // between the two catches
const CAST = 0.5;        // line going down
const HAUL = 1.0;        // card coming up
const RETRACT = 0.3;     // line going back
const LEAVE = 4.0;       // the boat sets off again

const clamp = (v) => Math.min(1, Math.max(0, v));
const easeOut = (v) => 1 - (1 - v) ** 3;
const easeIn = (v) => v ** 3;
const easeInOut = (v) => (v < 0.5 ? 4 * v ** 3 : 1 - (-2 * v + 2) ** 3 / 2);

/**
 * { boat, fishing, cards: [{ lift, line }], done }
 * boat: centre of the boat as a fraction of the scene width (outside 0..1 is off screen)
 * lift: 0 under water, 1 in place.  line: how far the fishing line reaches, 0..1.
 */
export function sceneAt(seconds, count = 2) {
  const t = Math.max(0, seconds);
  let boat = 0.5;
  if (t < ARRIVE) boat = -0.2 + 0.7 * easeOut(t / ARRIVE);
  else if (t > LEAVE) boat = 0.5 + 0.8 * easeIn(clamp((t - LEAVE) / (SCENE_SECONDS - LEAVE)));

  const cards = Array.from({ length: count }, (_, i) => {
    const cast = ARRIVE + i * STAGGER;
    const hauled = cast + CAST + HAUL;
    let line = clamp((t - cast) / CAST);
    if (t > hauled) line = 1 - clamp((t - hauled) / RETRACT);
    return { lift: easeInOut(clamp((t - cast - CAST) / HAUL)), line };
  });

  return { boat, fishing: t >= ARRIVE && t < LEAVE, cards, done: t >= SCENE_SECONDS };
}
