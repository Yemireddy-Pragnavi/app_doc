'use client';
import {useEffect,useState} from 'react';
import {animate,motion,useReducedMotion} from 'framer-motion';
export function AnimatedCounter({value}:{value:number}){const reduced=useReducedMotion();const [display,setDisplay]=useState(value);useEffect(()=>{if(reduced){setDisplay(value);return}const animation=animate(0,value,{duration:.95,ease:'easeOut',onUpdate:v=>setDisplay(Math.round(v))});return ()=>animation.stop()},[value,reduced]);return <>{display}</>}
export function AmbientMotion(){return <div className="ambient-motion" aria-hidden="true"><span/><span/><span/></div>}
export {motion,useReducedMotion};
