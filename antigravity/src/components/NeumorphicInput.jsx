import React from 'react';

const NeumorphicInput = ({ placeholder, type = 'text', value, onChange, className = '' }) => {
  return (
    <input
      type={type}
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      className={`
        w-full px-6 py-4 rounded-2xl bg-neo-bg-light shadow-neumorph-in
        focus:outline-none focus:ring-2 focus:ring-neo-accent-blue/30
        text-gray-700 placeholder-gray-400 transition-all duration-300
        ${className}
      `}
    />
  );
};

export default NeumorphicInput;
