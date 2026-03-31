import React from 'react';

const NeumorphicCard = ({ children, className = '', padding = 'p-8' }) => {
  return (
    <div 
      className={`rounded-[30px] bg-neo-bg-light shadow-neumorph-out ${padding} ${className}`}
    >
      {children}
    </div>
  );
};

export default NeumorphicCard;
