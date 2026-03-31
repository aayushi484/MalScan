import React from 'react';

const AntigravityLayout = ({ children }) => {
  return (
    <div className="min-h-screen bg-neo-bg-light text-gray-800 flex items-center justify-center p-6 sm:p-12 overflow-hidden selection:bg-neo-accent-mint selection:text-white transition-colors duration-300">
      <div className="w-full max-w-5xl rounded-[40px] p-2 relative">
        {/* Soft lighting overlay to emphasize the 'light source from top-left' rule */}
        <div className="absolute top-0 left-0 w-full h-full rounded-[40px] bg-gradient-to-br from-white/40 to-transparent pointer-events-none" />
        {children}
      </div>
    </div>
  );
};

export default AntigravityLayout;
