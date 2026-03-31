import React from 'react';
import { motion } from 'framer-motion';

const NeumorphicButton = ({ 
  children, 
  onClick, 
  className = '', 
  isActive = false, 
  isIcon = false,
  colorVariant = 'blue' // 'blue' or 'mint'
}) => {
  const accentColor = colorVariant === 'mint' ? 'text-neo-accent-mint' : 'text-neo-accent-blue';
  
  return (
    <motion.button
      onClick={onClick}
      className={`
        relative flex items-center justify-center font-medium transition-colors duration-300
        ${isIcon ? 'w-14 h-14 rounded-full' : 'px-8 py-3 rounded-2xl'}
        ${isActive ? accentColor : 'text-gray-600'}
        ${className}
      `}
      animate={{
        backgroundColor: '#E0E5EC',
        boxShadow: isActive 
          ? 'inset -9px -9px 16px rgba(255, 255, 255, 0.5), inset 9px 9px 16px rgba(163, 177, 198, 0.6)'
          : '-9px -9px 16px rgba(255, 255, 255, 0.5), 9px 9px 16px rgba(163, 177, 198, 0.6)'
      }}
      whileHover={isActive ? {} : {
        boxShadow: '-12px -12px 20px rgba(255, 255, 255, 0.6), 12px 12px 20px rgba(163, 177, 198, 0.7)'
      }}
      whileTap={{
        boxShadow: 'inset -9px -9px 16px rgba(255, 255, 255, 0.5), inset 9px 9px 16px rgba(163, 177, 198, 0.6)'
      }}
      transition={{ duration: 0.2, ease: "easeInOut" }}
    >
      {children}
    </motion.button>
  );
};

export default NeumorphicButton;
